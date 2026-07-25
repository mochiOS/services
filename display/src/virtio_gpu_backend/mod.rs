mod control;
mod display_info;
mod dma;
mod driver;
mod error;
mod pci;
mod presenter;
mod resource;

pub(crate) use driver::VirtioGpuBackend;
pub(crate) use error::GpuError;
