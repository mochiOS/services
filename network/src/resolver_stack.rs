// Included in stack.rs so the adapter alone can access private packet tables.
impl NetworkStack {
    fn with_dns<R>(
        &mut self,
        action: impl FnOnce(
            &mut crate::resolver::Resolver<UdpSocketId, crate::stream::Socket>,
            &mut Self,
        ) -> R,
    ) -> Result<R, i32> {
        // DNS I/O only accesses packet tables, never re-enters the resolver.
        let mut dns = self.dns.take().ok_or(-5)?;
        let result = action(&mut dns, self);
        let stats = dns.statistics;
        self.stats.dns_queries = stats.queries;
        self.stats.dns_cache_hits = stats.cache_hits;
        self.stats.dns_cache_misses = stats.cache_misses;
        self.stats.dns_failures = stats.failures;
        self.stats.dns_timeouts = stats.timeouts;
        self.dns = Some(dns);
        Ok(result)
    }

    pub(crate) fn start_dns(
        &mut self,
        name: DnsRecordName,
        kind: DnsRecordType,
        now: u64,
        timeout: u64,
    ) -> Result<crate::resolver::Query, i32> {
        self.with_dns(|dns, stack| dns.start(stack, name, kind, now, timeout))?
    }
    pub(crate) fn pump_dns(&mut self, now: u64) {
        let _ = self.with_dns(|dns, stack| dns.pump(stack, now));
    }
    pub(crate) fn take_dns(
        &mut self,
        id: crate::resolver::Query,
    ) -> Result<Option<Result<crate::resolver::Answer, crate::resolver::Failure>>, i32> {
        self.with_dns(|dns, _| dns.take(id))?
    }
    pub(crate) fn cancel_dns(&mut self, id: crate::resolver::Query, now: u64) -> Result<(), i32> {
        self.with_dns(|dns, stack| dns.cancel(stack, id, now))?
    }

    fn take_dns_ipv4(
        &mut self,
        id: crate::resolver::Query,
    ) -> Result<Option<([u8; 4], bool)>, u64> {
        let Some(result) = self.take_dns(id).map_err(|error| error as i64 as u64)? else {
            return Ok(None);
        };
        let answer = result.map_err(|error| error.status() as i64 as u64)?;
        match answer.records.values().first() {
            Some(DnsRecordValue::Ipv4(address)) => Ok(Some((*address, answer.from_cache))),
            _ => Err(mochios_net_device_protocol::STATUS_UNSUPPORTED_RECORD as i64 as u64),
        }
    }

    // Older HTTP/TLS entry points are themselves synchronous. They drive the
    // same jobs, including other clients' pending queries, rather than keeping
    // a second DNS implementation. The ResolveIpv4 RPC uses the async path.
    pub(crate) fn resolve_ipv4(
        &mut self,
        hostname: &str,
        started: u64,
        timeout: u64,
    ) -> Result<([u8; 4], bool), u64> {
        if let Some(address) = parse_ipv4_literal(hostname) {
            return Ok((address, false));
        }
        let name =
            crate::resolver::hostname(hostname).map_err(|error| error.status() as i64 as u64)?;
        let id = self
            .start_dns(name, DnsRecordType::A, started, timeout)
            .map_err(|error| error as i64 as u64)?;
        loop {
            if let Some(answer) = self.take_dns_ipv4(id)? {
                return Ok(answer);
            }
            let now = match platform::time::ticks() {
                Ok(now) => now,
                Err(error) => {
                    let _ = self.cancel_dns(id, started);
                    return Err(error.raw().unsigned_abs());
                }
            };
            self.tcp
                .advance(now, || platform::service_ready::generate_token().ok());
            self.tick(now);
            if let Some(answer) = self.take_dns_ipv4(id)? {
                return Ok(answer);
            }
            for _ in 0..32 {
                match self.poll_receive(now) {
                    Ok(true) => (),
                    Ok(false) => break,
                    Err(error) => {
                        let _ = self.cancel_dns(id, now);
                        return Err(error);
                    }
                }
            }
            self.pump_dns(now);
            if let Some(answer) = self.take_dns_ipv4(id)? {
                return Ok(answer);
            }
            platform::thread::yield_now();
        }
    }
}

impl crate::resolver::Transport for NetworkStack {
    type Datagram = UdpSocketId;
    type Stream = crate::stream::Socket;
    fn context(&self) -> Result<Ipv4Config, i32> {
        self.config
            .filter(|c| c.address != [0; 4] && c.dns != [0; 4])
            .ok_or(mochios_net_device_protocol::STATUS_NETWORK_UNAVAILABLE as i32)
    }
    fn entropy(&mut self) -> Result<u64, i32> {
        platform::service_ready::generate_token()
            .map_err(|error| crate::status::failure_status(error.raw() as u64))
    }
    fn open_datagram(&mut self, server: [u8; 4], entropy: u64) -> Result<UdpSocketId, i32> {
        let local = <Self as crate::resolver::Transport>::context(self)?.address;
        for offset in 0..32u32 {
            let port = 1024 + ((entropy % 64512 + u64::from(offset)) % 64512) as u16;
            match self.udp.bind_endpoint(local, port) {
                Ok(socket) => {
                    if self
                        .udp
                        .set_peer(
                            socket,
                            Some(UdpEndpoint {
                                address: server,
                                port: DNS_PORT,
                            }),
                        )
                        .is_err()
                    {
                        self.udp.unbind_endpoint(socket);
                        return Err(-5);
                    }
                    return Ok(socket);
                }
                Err(PacketError::Mismatch) => continue,
                Err(_) => return Err(-11),
            }
        }
        Err(-11)
    }
    fn send_datagram(&mut self, socket: UdpSocketId, data: &[u8], now: u64) -> Result<(), i32> {
        let local = self.udp.local_endpoint(socket).map_err(|_| -9)?;
        let peer = self.udp.peer(socket).map_err(|_| -9)?.ok_or(-5)?;
        self.send_udp(local.port, peer.port, peer.address, data, now)
            .map_err(crate::status::failure_status)
    }
    fn receive_datagram(&mut self, socket: UdpSocketId) -> Result<Option<Vec<u8>>, i32> {
        let local = self.udp.local_endpoint(socket).map_err(|_| -9)?;
        let peer = self.udp.peer(socket).map_err(|_| -9)?.ok_or(-5)?;
        let Some(packet) = self.udp.receive_for(socket).map_err(|_| -9)? else {
            return Ok(None);
        };
        if packet.source_address != peer.address
            || packet.source_port != peer.port
            || packet.destination_address != local.address
            || packet.destination_port != local.port
        {
            return Ok(None);
        }
        Ok(Some(packet.payload))
    }
    fn close_datagram(&mut self, socket: UdpSocketId) {
        self.udp.unbind_endpoint(socket);
    }
    fn open_stream(&mut self, server: [u8; 4], entropy: u64) -> Result<crate::stream::Socket, i32> {
        let socket = self.tcp.open()?;
        if let Err(error) = self.tcp.connect(
            socket,
            mochios_net_device_protocol::datagram::Endpoint {
                address: server,
                port: DNS_PORT,
            },
            || Some(entropy),
        ) {
            self.tcp.release(socket, 0);
            return Err(error);
        }
        Ok(socket)
    }
    fn stream_connected(&mut self, socket: crate::stream::Socket) -> Result<bool, i32> {
        let status = self.tcp.status(socket)?;
        if status.error != 0 {
            return Err(status.error);
        }
        if status.peer_closed && !status.writable {
            return Err(-104);
        }
        Ok(!status.connecting && status.writable)
    }
    fn send_stream(&mut self, socket: crate::stream::Socket, data: &[u8]) -> Result<usize, i32> {
        self.tcp.send(socket, data)
    }
    fn receive_stream(
        &mut self,
        socket: crate::stream::Socket,
        data: &mut [u8],
    ) -> Result<usize, i32> {
        self.tcp.receive(socket, false, data)
    }
    fn close_stream(&mut self, socket: crate::stream::Socket, now: u64) {
        self.tcp.release(socket, now);
    }
}

impl crate::resolver_rpc::Backend for NetworkStack {
    type Query = crate::resolver::Query;
    fn start(&mut self, name: DnsRecordName, now: u64, timeout: u64) -> Result<Self::Query, i32> {
        self.start_dns(name, DnsRecordType::A, now, timeout)
    }
    fn take(
        &mut self,
        id: Self::Query,
    ) -> Result<Option<Result<crate::resolver::Answer, crate::resolver::Failure>>, i32> {
        self.take_dns(id)
    }
}

impl crate::resolver_backend::Backend for NetworkStack {
    type Query = crate::resolver::Query;
    fn start(
        &mut self,
        name: DnsRecordName,
        kind: DnsRecordType,
        now: u64,
        timeout: u64,
    ) -> Result<Self::Query, i32> {
        self.start_dns(name, kind, now, timeout)
    }
    fn take(
        &mut self,
        id: Self::Query,
    ) -> Result<Option<Result<crate::resolver::Answer, crate::resolver::Failure>>, i32> {
        self.take_dns(id)
    }
    fn cancel(&mut self, id: Self::Query, now: u64) -> Result<(), i32> {
        self.cancel_dns(id, now)
    }
}
