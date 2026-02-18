pub mod dkg_service {
    tonic::include_proto!("dkg_service");
}

pub mod pre_service {
    tonic::include_proto!("pre_service");
}

pub mod info_service {
    tonic::include_proto!("info_service");
}

pub mod store_secret_service {
    tonic::include_proto!("store_secret_service");
}

pub mod utility_service {
    tonic::include_proto!("orbis.utility.v1");
}
