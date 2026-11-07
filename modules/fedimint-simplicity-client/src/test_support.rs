macro_rules! impl_mock_federation_api {
    ($api:ty; $($methods:tt)*) => {
        #[async_trait::async_trait]
        impl fedimint_api_client::api::IRawFederationApi for $api {
            $($methods)*

            fn self_peer(&self) -> Option<fedimint_core::PeerId> {
                None
            }

            fn connection_status_stream(
                &self,
            ) -> futures::stream::BoxStream<
                'static,
                std::collections::BTreeMap<fedimint_core::PeerId, fedimint_connectors::PeerStatus>,
            > {
                Box::pin(futures::stream::empty())
            }

            async fn wait_for_initialized_connections(&self) {}

            async fn get_peer_connection(
                &self,
                _: fedimint_core::PeerId,
            ) -> fedimint_connectors::ServerResult<fedimint_connectors::DynGuaridianConnection> {
                panic!("unexpected connection")
            }
        }
    };
}

pub(crate) use impl_mock_federation_api;
