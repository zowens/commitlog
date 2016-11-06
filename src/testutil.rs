use std::fs;

pub struct TestFile {
    path: &'static str,
}

impl TestFile {
    pub fn new(path: &'static str) -> TestFile {
        fs::remove_file(path).unwrap_or(());
        TestFile { path: path }
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        fs::remove_file(self.path).unwrap_or(());
    }
}
