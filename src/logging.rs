pub(crate) struct Spammable<'why> {
    why: &'why str,
    warning: String,
    count: usize,
}

impl<'why> Spammable<'why> {
    pub(crate) fn new(why: &'why str) -> Self {
        Self {
            why,
            warning: String::default(),
            count: 0,
        }
    }

    pub(crate) fn warn<F>(&mut self, warning: F)
    where
        F: FnOnce() -> String,
    {
        if self.count > 0 {
            self.warning = warning();
        }
        self.count += 1;
    }
}

impl Drop for Spammable<'_> {
    fn drop(&mut self) {
        if self.count > 0 {
            log::warn!("{}", self.warning);
            if self.count > 1 {
                log::warn!("and {} others...", self.count);
            }
            log::warn!("^^ {}", self.why);
        }
    }
}
