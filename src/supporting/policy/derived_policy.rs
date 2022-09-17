use std::iter::Map;

struct SignedPolicyReference {
    pub reference: PolicyReference,
    pub signature: String,
}
struct PolicyReference{
    pub nextId: String,
    pub signature: String,
    pub issued: String,
    pub expires: String,
}

struct SignedPolicy{
    pub policy: Policy,
    pub signature: String,
}
struct Policy{
    pub name: String,
    pub derives: Map<String,PolicyReference>,
}
