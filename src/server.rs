use std::hash::Hash;
// Import necessary modules from Tonic and other dependencies.
use tonic::{transport::Server, Code, Request, Response,Status,codegen::http::request};
use num_bigint::BigUint;
use std::sync::Mutex;
use std::collections::HashMap;


pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
// Import types and traits related to the Auth service from the generated code.
use zkp_auth::{auth_server::{Auth,AuthServer},RegisterRequest,RegisterResponse,AuthenticationChallengeRequest,AuthenticationChallengeResponse,AuthenticationAnswerRequest,AuthenticationAnswerResponse};
// Define a struct to implement the Auth service.
#[derive(Debug,Default)]
pub struct AuthImpl{
    pub user_info: Mutex<HashMap<String, UserInfo>>,
}
#[derive(Debug,Default)]
pub struct UserInfo{
    //registration
    pub user_name: String,
    pub y1 : BigUint,
    pub y2: BigUint,
    //authorization
    pub r1:  BigUint,
    pub r2:  BigUint,
    //verification
    pub c:  BigUint,
    pub s:  BigUint,
    pub session_id:  BigUint,
}
// Implement the Auth trait for the AuthImpl struct.
// This trait contains the service methods as defined in the .proto file.
#[tonic::async_trait]
impl Auth for AuthImpl{
    // Implement the `register` method from the Auth service.
    // This method is asynchronous and handles registration requests.
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>,Status>{
        println!("Processing Register: {:?}",request);
        let request = request.into_inner();

        let user_name = request.name;


        let mut new_user_info = UserInfo::default();
        new_user_info.user_name = user_name.clone();
        new_user_info.y1 = BigUint::from_bytes_be(&request.y1);
        new_user_info.y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_info_map = self.user_info.lock().unwrap();
        user_info_map.insert(user_name, new_user_info);

        Ok(Response::new(RegisterResponse{}))
    }
    // Implement the `create_authentication_challenge` method.
    // This method handles requests to create an authentication challenge.
    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>,Status>{
        todo!()
    }
    // Implement the `verify_authentication` method.
    // This method handles requests to verify an authentication response.
    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>,Status>{
        todo!()
    }
}
#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();
    println!("Running the server in {}", addr);
    // Build and run the server.
    Server::builder()
        // Add the Auth service to the server.
        .add_service(AuthServer::new(AuthImpl::default()))
        // Start serving requests on the specified address.
        // If the address is invalid, the program will panic with the specified error message.
        .serve(addr.parse().expect("Couldn't convert address"))
        // Await the server to run until it's terminated.
        .await
        // Unwrap the Result, panicking if the server fails to start (e.g., if the port is already in use).
        .unwrap();
}

