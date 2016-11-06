use std::fs;
use std::path::Path;

pub struct TestFile<'a> {
    path: &'a Path,
}

impl<'a> TestFile<'a> {
    pub fn new(path: &'a Path) -> TestFile<'a> {
        TestFile { path: path }
    }

    pub fn new_fresh(path: &'a Path) -> TestFile<'a> {
        fs::remove_file(path).unwrap_or(());
        TestFile { path: path }
    }
}

impl<'a> Drop for TestFile<'a> {
    fn drop(&mut self) {
        fs::remove_file(self.path).unwrap_or(());
    }
}
