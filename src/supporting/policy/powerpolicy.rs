use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::trust::certmgr::SignedCertificateRequest;

pub struct PolicyValidatorResponse{
    pub valid: bool,
    pub confidence: u32,
}
pub trait PolicyValidator{
    fn validate<H:Hivemind>(&self, request: SignedCertificateRequest, hivemind: &H) -> PolicyValidatorResponse;

}