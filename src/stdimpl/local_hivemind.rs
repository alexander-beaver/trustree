use crate::supporting::datastore::hivemind::Hivemind;

struct LocalHivemind{
    directory: String,
}
impl LocalHivemind{

}
fn dir_exists(folder: String) -> bool{
    return std::path::Path::new(&format!("{}", folder)).is_dir();
}
impl Hivemind for LocalHivemind{
    fn init(&self) -> bool{
        // Create all folders to the directory if they do not exist
        if dir_exists(self.directory.clone()){
            std::fs::create_dir_all(self.directory.clone()).expect("Unable to create directory");

        }
        return true;

    }

    fn exists(&self, key: &str) -> bool {
        return std::path::Path::new(&format!("{}/{}", self.directory, key)).exists();
    }

    fn get(&self, key: &str) -> Option<String> {
        if self.exists(key){
            let contents = std::fs::read_to_string(&format!("{}/{}", self.directory, key)).expect("Unable to read file");
            return Some(contents);
        }else{
            return None;
        }
    }

    fn set(&mut self, key: &str, value: &str) {
        std::fs::write(&format!("{}/{}", self.directory, key), value).expect("Unable to write file");
    }

    fn delete(&mut self, key: &str) {
        std::fs::remove_file(&format!("{}/{}", self.directory, key)).expect("Unable to delete file");
    }
}