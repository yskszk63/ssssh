pub(crate) trait Named {
    fn name(&self) -> &'static str;
}
