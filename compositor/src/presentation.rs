//! Compositor-owned lifecycle of an expected protected presentation.
//! Observations come from native owner/Surface state, never renderer feedback.
use alloc::vec::Vec;
use mochi_user_platform::capability::{
    consent::Correlation,
    presentation::{Context, Image, Kind, Receipt, Stage},
};
pub(crate) const MAX_REGISTRATIONS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SurfaceKey {
    pub token: u64,
    pub client: u64,
    pub sender: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct Observation {
    pub image: Image,
    pub surface: SurfaceKey,
    pub content: u64,
    pub focus: u64,
    pub focused: bool,
    pub visible: bool,
    pub unobscured: bool,
    pub ready: bool,
}
struct Entry<H> {
    broker: u64,
    correlation: Correlation,
    kind: Kind,
    renderer: H,
    receipt: Receipt,
    bound: Option<(SurfaceKey, u64, u64)>,
}
pub(crate) struct Registry<H> {
    context: Option<Context>,
    next: Option<u64>,
    entries: Vec<Entry<H>>,
}
impl<H> Default for Registry<H> {
    fn default() -> Self {
        Self {
            context: None,
            next: Some(1),
            entries: Vec::new(),
        }
    }
}
impl<H> Registry<H> {
    pub fn context(&self) -> Option<Context> {
        self.context
    }
    pub fn update_context(&mut self, context: Context) -> Result<(), u32> {
        if !context.valid()
            || self.context.is_some_and(|old| {
                context.generation < old.generation
                    || (context.generation == old.generation
                        && (context.active || context.session != old.session))
            })
        {
            return Err(22);
        }
        self.entries.clear();
        self.context = Some(context);
        Ok(())
    }
    pub fn register(
        &mut self,
        broker: u64,
        context: Context,
        correlation: Correlation,
        kind: Kind,
        renderer: H,
        image: Image,
    ) -> Result<Receipt, u32> {
        if broker == 0
            || image.process == 0
            || !context.active
            || self.context != Some(context)
            || !correlation.ticket.is_valid()
            || correlation.display == 0
        {
            return Err(13);
        }
        if self.entries.iter().any(|e| e.correlation == correlation) {
            return Err(16);
        }
        if self.entries.len() == MAX_REGISTRATIONS {
            return Err(28);
        }
        self.entries.try_reserve(1).map_err(|_| 12u32)?;
        let registration = self.next.ok_or(75u32)?;
        self.next = registration.checked_add(1);
        let receipt = Receipt {
            status: 0,
            stage: Stage::Pending,
            registration,
            context,
            focus_generation: 0,
            surface: 0,
            content_generation: 0,
            renderer: image,
        };
        self.entries.push(Entry {
            broker,
            correlation,
            kind,
            renderer,
            receipt,
            bound: None,
        });
        Ok(receipt)
    }
    pub fn expected(&self, correlation: Correlation) -> Result<(&H, Image, Kind), u32> {
        let e = self
            .entries
            .iter()
            .find(|e| e.correlation == correlation)
            .ok_or(2u32)?;
        Ok((&e.renderer, e.receipt.renderer, e.kind))
    }
    pub fn bind(
        &mut self,
        correlation: Correlation,
        observation: Observation,
    ) -> Result<Receipt, u32> {
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.correlation == correlation)
            .ok_or(2u32)?;
        if e.bound.is_some() || e.receipt.stage != Stage::Pending {
            return Err(16);
        }
        if observation.image != e.receipt.renderer
            || observation.surface.token == 0
            || observation.surface.client == 0
            || observation.surface.sender == 0
            || observation.focus == 0
            || !observation.focused
        {
            return Err(13);
        }
        e.bound = Some((observation.surface, observation.content, observation.focus));
        e.receipt.surface = observation.surface.token;
        Ok(e.receipt)
    }
    fn update_entry(e: &mut Entry<H>, observation: Option<Observation>, presented: bool) -> bool {
        let Some((surface, baseline, focus)) = e.bound else {
            return false;
        };
        if e.receipt.stage == Stage::Revoked {
            return false;
        }
        let Some(o) = observation.filter(|o| {
            o.image == e.receipt.renderer
                && o.surface == surface
                && o.focus == focus
                && o.focus != 0
                && o.focused
                && o.visible
                && o.unobscured
                && o.content >= baseline
        }) else {
            e.receipt.stage = Stage::Revoked;
            return false;
        };
        let fresh = e.receipt.stage == Stage::Pending && o.ready && o.content > baseline;
        if fresh && presented {
            e.receipt.stage = Stage::Presented;
            e.receipt.content_generation = o.content;
            e.receipt.focus_generation = focus;
        }
        fresh
    }
    /// Returns whether a full present is required. A commit/queued frame alone
    /// never marks a registration as presented, and a failed present does not.
    pub fn observe(
        &mut self,
        mut observation: impl FnMut(&H, SurfaceKey) -> Option<Observation>,
    ) -> bool {
        let mut needs_frame = false;
        for e in &mut self.entries {
            let value = e
                .bound
                .and_then(|(surface, _, _)| observation(&e.renderer, surface));
            needs_frame |= Self::update_entry(e, value, false);
        }
        needs_frame
    }
    pub fn full_presented(
        &mut self,
        mut observation: impl FnMut(&H, SurfaceKey) -> Option<Observation>,
    ) {
        for e in &mut self.entries {
            let value = e
                .bound
                .and_then(|(surface, _, _)| observation(&e.renderer, surface));
            Self::update_entry(e, value, true);
        }
    }
    pub fn status(
        &self,
        broker: u64,
        correlation: Correlation,
        registration: u64,
    ) -> Result<Receipt, u32> {
        let e = self
            .entries
            .iter()
            .find(|e| e.correlation == correlation && e.receipt.registration == registration)
            .ok_or(2u32)?;
        if e.broker != broker {
            return Err(13);
        }
        Ok(e.receipt)
    }
    pub fn cancel(
        &mut self,
        broker: u64,
        correlation: Correlation,
        registration: u64,
    ) -> Result<Receipt, u32> {
        self.status(broker, correlation, registration)?;
        let at = self
            .entries
            .iter()
            .position(|e| e.receipt.registration == registration)
            .ok_or(2u32)?;
        let e = self.entries.remove(at);
        Ok(Receipt {
            stage: Stage::Revoked,
            ..e.receipt
        })
    }
}
