use super::*;

impl<H: Copy> PosixService<H> {
    /// Sender identity was validated against the authenticated endpoint by the
    /// thread request dispatcher. Request bytes contain only a delivery token.
    pub(super) fn signal_delivery_origin_payload(
        &self,
        sender: mnu_abi::ExecutionIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        let delivery = protocol::decode_signal_delivery(payload).map_err(|_| STATUS_EINVAL)?;
        if delivery.token == 0 {
            return Err(STATUS_EINVAL);
        }
        let owner = self
            .process_wait_states
            .get(&sender.process_id)
            .and_then(|state| state.deliveries.get(&delivery.token))
            .filter(|owner| owner.thread_id == sender.thread_id && owner.signal == delivery.signal)
            .ok_or(protocol::STATUS_EAGAIN)?;
        let mut output = vec![0; protocol::signal_origin::LEN];
        protocol::signal_origin::encode(owner.origin, &mut output).map_err(|_| STATUS_EINVAL)?;
        Ok(output)
    }
}
