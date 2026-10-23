use super::*;

impl<H: Copy> PosixService<H> {
    /// Called only after endpoint-authenticated process/thread validation.
    pub(super) fn thread_fault_signal_payload(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        let request = protocol::decode_signal_send_request(payload).map_err(|_| STATUS_EINVAL)?;
        if request.selector != 0
            || !matches!(request.signal, protocol::SIGNAL_BUS | protocol::SIGNAL_SEGV)
        {
            return Err(STATUS_EINVAL);
        }
        let key = (sender.process_id, sender.thread_id);
        let blocked = self.signal_masks.get(&key).ok_or(protocol::STATUS_ESRCH)?;
        let disposition = self
            .signals
            .get(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .disposition(request.signal);
        let disposition = if blocked & signal_bit(request.signal) == 0
            && disposition == protocol::SIGNAL_DISPOSITION_CAUGHT
        {
            protocol::SIGNAL_DISPOSITION_CAUGHT
        } else {
            protocol::SIGNAL_DISPOSITION_DEFAULT
        };
        // No pending bit is consumed or notification enqueued. This fault is
        // already executing on the caller's native exception callback stack.
        let signal = self.begin_signal_delivery(
            sender,
            request.signal,
            protocol::signal_origin::Origin {
                source: protocol::signal_origin::FAULT,
                real_uid: 0,
                process_id: 0,
                ..protocol::signal_origin::Origin::system()
            },
        )?;
        let mut output = vec![0; protocol::fault_signal::DELIVERY_LEN];
        protocol::fault_signal::encode(
            protocol::fault_signal::Delivery {
                signal,
                disposition,
            },
            &mut output,
        )
        .map_err(|_| STATUS_EINVAL)?;
        Ok(output)
    }

    pub(super) fn begin_signal_delivery(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        signal: u32,
        origin: protocol::signal_origin::Origin,
    ) -> Result<protocol::SignalDelivery, i32> {
        let state = self
            .process_wait_states
            .get_mut(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if state.deliveries.len() >= MAX_OUTSTANDING_SIGNAL_DELIVERIES {
            return Err(protocol::STATUS_EAGAIN);
        }
        let epoch = self
            .signal_delivery_epochs
            .entry((sender.process_id, sender.thread_id))
            .or_insert(0);
        let next_epoch = epoch.checked_add(1).ok_or(STATUS_EOVERFLOW)?;
        let token = signal_dequeue::allocate_token(&mut self.next_signal_delivery_token)?;
        let delivery = protocol::SignalDelivery { signal, token };
        state.begin_delivery(delivery, sender.thread_id, origin);
        *epoch = next_epoch;
        Ok(delivery)
    }
}
