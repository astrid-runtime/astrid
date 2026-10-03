//! Store-owned execution accounting. The Store outlives a cancelled guest
//! future, so its drop path can settle the last observable fuel sample.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::user_cpu::throttle::ExecutionThrottle;
use wasmtime::{AsContext, AsContextMut, Store, StoreContext, StoreContextMut};

#[cfg(test)]
mod tests;

#[derive(Clone)]
struct Meter {
    remaining: Arc<AtomicU64>,
    allowance: Arc<AtomicU64>,
    throttle: ExecutionThrottle,
}

impl Meter {
    fn observe(&self, remaining: u64) -> wasmtime::Result<()> {
        let previous = self.remaining.load(Ordering::Relaxed);
        let spent = previous.checked_sub(remaining).ok_or_else(|| {
            wasmtime::Error::msg("fuel increased without resetting its accounting baseline")
        })?;
        self.remaining.store(remaining, Ordering::Relaxed);
        self.throttle.charge(spent);
        Ok(())
    }

    fn check_allowance(&self) -> wasmtime::Result<()> {
        if u64::MAX - self.remaining.load(Ordering::Relaxed)
            > self.allowance.load(Ordering::Relaxed)
        {
            return Err(wasmtime::Trap::OutOfFuel.into());
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T: Send> wasmtime::CallHookHandler<T> for Meter {
    async fn handle_call_event(
        &self,
        store: StoreContextMut<'_, T>,
        event: wasmtime::CallHook,
    ) -> wasmtime::Result<()> {
        self.observe(store.get_fuel()?)?;
        self.check_allowance()?;
        if event.exiting_host() {
            self.throttle.wait().await;
        }
        Ok(())
    }
}

pub(super) struct AccountedStore<T: Send + 'static> {
    store: Store<T>,
    meter: Option<Meter>,
}

impl<T: Send + 'static> AccountedStore<T> {
    pub(super) fn new(
        store: Store<T>,
        throttle: Option<ExecutionThrottle>,
    ) -> wasmtime::Result<Self> {
        let mut accounted = Self { store, meter: None };
        accounted.bind_throttle(throttle)?;
        Ok(accounted)
    }

    /// Rebind an authenticated invocation, settling the previous authority
    /// before changing the store's principal/user accounting.
    pub(super) fn bind_throttle(
        &mut self,
        throttle: Option<ExecutionThrottle>,
    ) -> wasmtime::Result<()> {
        self.settle()?;
        let initial_allowance = self.store.get_fuel()?;
        self.meter = if let Some(throttle) = throttle {
            // Keep a large measurement counter independent of the call cap.
            // A small counter clamps to zero after a bulk operation and loses
            // the amount of overshoot we must charge to the shared user.
            self.store.set_fuel(u64::MAX)?;
            let meter = Meter {
                remaining: Arc::new(AtomicU64::new(u64::MAX)),
                allowance: Arc::new(AtomicU64::new(initial_allowance)),
                throttle,
            };
            self.store
                .fuel_async_yield_interval(Some(meter.throttle.sampling_fuel()))?;
            self.store.call_hook_async(meter.clone());
            Some(meter)
        } else {
            self.store.call_hook(|_, _| Ok(()));
            self.store.fuel_async_yield_interval(None)?;
            None
        };
        Ok(())
    }

    pub(super) fn set_fuel(&mut self, fuel: u64) -> wasmtime::Result<()> {
        self.settle()?;
        if let Some(meter) = &self.meter {
            self.store.set_fuel(u64::MAX)?;
            meter.remaining.store(u64::MAX, Ordering::Relaxed);
            meter.allowance.store(fuel, Ordering::Relaxed);
        } else {
            self.store.set_fuel(fuel)?;
        }
        Ok(())
    }

    pub(super) fn settle(&self) -> wasmtime::Result<()> {
        if let Some(meter) = &self.meter {
            meter.observe(self.store.get_fuel()?)?;
        }
        Ok(())
    }

    /// Return false for the unchanged personal scheduler. Configured user
    /// execution waits instead of discarding a long-running guest's state.
    pub(super) fn configure_rate_epochs(&mut self, ticks: u64) -> bool {
        let Some(meter) = self.meter.clone() else {
            return false;
        };
        self.store.set_epoch_deadline(ticks);
        self.store.epoch_deadline_callback(move |context| {
            meter.observe(context.get_fuel()?)?;
            meter.check_allowance()?;
            let throttle = meter.throttle.clone();
            Ok(wasmtime::UpdateDeadline::YieldCustom(
                ticks,
                Box::pin(async move { throttle.wait().await }),
            ))
        });
        true
    }
}

impl<T: Send + 'static> Drop for AccountedStore<T> {
    fn drop(&mut self) {
        if let Err(error) = self.settle() {
            tracing::error!(%error, "failed to settle guest execution accounting");
        }
    }
}

impl<T: Send + 'static> Deref for AccountedStore<T> {
    type Target = Store<T>;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl<T: Send + 'static> DerefMut for AccountedStore<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
}

impl<T: Send + 'static> AsContext for AccountedStore<T> {
    type Data = T;
    fn as_context(&self) -> StoreContext<'_, T> {
        self.store.as_context()
    }
}

impl<T: Send + 'static> AsContextMut for AccountedStore<T> {
    fn as_context_mut(&mut self) -> StoreContextMut<'_, T> {
        self.store.as_context_mut()
    }
}
