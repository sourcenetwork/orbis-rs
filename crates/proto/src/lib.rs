pub mod info_service {
    tonic::include_proto!("orbis.v0.info_service");
}

pub mod unsafe_testing {
    tonic::include_proto!("orbis.unsafe_testing");
}

pub mod v0 {
    pub mod dkg {
        tonic::include_proto!("orbis.v0.dkg");
    }

    pub mod pre {
        tonic::include_proto!("orbis.v0.pre");
    }

    pub mod sign {
        tonic::include_proto!("orbis.v0.sign");
    }

    pub mod store_secret {
        tonic::include_proto!("orbis.v0.store_secret");
    }
}

#[cfg(test)]
mod tests {
    use super::v0::{dkg, pre, sign, store_secret};
    use tonic::server::NamedService;

    struct Services;

    #[tonic::async_trait]
    impl dkg::dkg_service_server::DkgService for Services {
        async fn start_dkg(
            &self,
            _: tonic::Request<dkg::StartDkgRequest>,
        ) -> Result<tonic::Response<dkg::StartDkgResponse>, tonic::Status> {
            unreachable!()
        }

        async fn get_dkg_session_status(
            &self,
            _: tonic::Request<dkg::GetDkgSessionStatusRequest>,
        ) -> Result<tonic::Response<dkg::GetDkgSessionStatusResponse>, tonic::Status> {
            unreachable!()
        }
    }

    #[tonic::async_trait]
    impl pre::pre_service_server::PreService for Services {
        async fn start_pre(
            &self,
            _: tonic::Request<pre::StartPreRequest>,
        ) -> Result<tonic::Response<pre::StartPreResponse>, tonic::Status> {
            unreachable!()
        }
    }

    #[tonic::async_trait]
    impl sign::sign_service_server::SignService for Services {
        async fn start_sign(
            &self,
            _: tonic::Request<sign::StartSignRequest>,
        ) -> Result<tonic::Response<sign::StartSignResponse>, tonic::Status> {
            unreachable!()
        }
    }

    #[tonic::async_trait]
    impl store_secret::store_secret_service_server::StoreSecretService for Services {
        async fn store_secret(
            &self,
            _: tonic::Request<store_secret::StoreSecretRequest>,
        ) -> Result<tonic::Response<store_secret::StoreSecretResponse>, tonic::Status> {
            unreachable!()
        }
    }

    #[test]
    fn v0_service_names_are_versioned() {
        assert_eq!(
            <dkg::dkg_service_server::DkgServiceServer<Services> as NamedService>::NAME,
            "orbis.v0.dkg.DkgService"
        );
        assert_eq!(
            <pre::pre_service_server::PreServiceServer<Services> as NamedService>::NAME,
            "orbis.v0.pre.PreService"
        );
        assert_eq!(
            <sign::sign_service_server::SignServiceServer<Services> as NamedService>::NAME,
            "orbis.v0.sign.SignService"
        );
        assert_eq!(
            <store_secret::store_secret_service_server::StoreSecretServiceServer<
                Services,
            > as NamedService>::NAME,
            "orbis.v0.store_secret.StoreSecretService"
        );
    }
}
