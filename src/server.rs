
// Import necessary modules from Tonic and other dependencies.
use tonic::{transport::Server, Code, Request, Response,Status};
use num_bigint::BigUint;
use std::sync::Mutex;
use std::collections::HashMap;
use rust_zero_knowledge::ZKP;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
// Import types and traits related to the Auth service from the generated code.
use zkp_auth::{auth_server::{Auth,AuthServer},RegisterRequest,RegisterResponse,AuthenticationChallengeRequest,AuthenticationChallengeResponse,AuthenticationAnswerRequest,AuthenticationAnswerResponse};
// Define a struct to implement the Auth service.
#[derive(Debug,Default)]
pub struct AuthImpl{
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    //another hashmap to store relationship between user and auth_id
    pub auth_id_to_user:Mutex<HashMap<String,String>>,
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

        let user_name = request.user;


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
        println!("Processing Authentication");
        let request = request.into_inner();

        let user_name = request.user;

        let mut user_info_map = self.user_info.lock().unwrap();

        // Use `get_mut` on the `HashMap` to get a mutable reference to the `UserInfo`
        if let Some(user_info) = user_info_map.get_mut(&user_name) {

            let(_,_,_,q)=ZKP::get_constants();
            //challenge numbere
            let c = ZKP::generate_random_below(&q);
            let auth_id = ZKP::generate_random_string(12);

            user_info.c = c.clone();
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 =BigUint::from_bytes_be(&request.r2);

            let auth_id_to_user_map = &mut self.auth_id_to_user.lock().unwrap();
            auth_id_to_user_map.insert(auth_id.clone(),user_name);

            Ok(Response::new(AuthenticationChallengeResponse{auth_id,c:c.to_bytes_be()}))
        }else{
            Err(Status::new(Code::NotFound,format!("User: {} not found in database",user_name)))
        }
    }
    // Implement the `verify_authentication` method.
    // This method handles requests to verify an authentication response.
// Asynchronously verifies the authentication response
async fn verify_authentication(
    &self,
    request: Request<AuthenticationAnswerRequest>,
) -> Result<Response<AuthenticationAnswerResponse>, Status> {
    let request = request.into_inner();

    let auth_id = request.auth_id;
    println!("Processing Challenge Solution auth_id: {:?}", auth_id);

    let auth_id_to_user_hashmap = &mut self.auth_id_to_user.lock().unwrap();

    if let Some(user_name) = auth_id_to_user_hashmap.get(&auth_id) {
        let user_info_hashmap = &mut self.user_info.lock().unwrap();
        let user_info = user_info_hashmap
            .get_mut(user_name)
            .expect("AuthId not found on hashmap");

        let s = BigUint::from_bytes_be(&request.s);
        user_info.s = s;

        let (alpha, beta, p, q) = ZKP::get_constants();
        let zkp = ZKP { alpha, beta, p, q };

        let verification = zkp.verify(
            &user_info.r1,
            &user_info.r2,
            &user_info.y1,
            &user_info.y2,
            &user_info.c,
            &user_info.s,
        );

        if verification {
            let session_id = ZKP::generate_random_string(12);

            println!("Correct Challenge Solution username: {:?}", user_name);

            Ok(Response::new(AuthenticationAnswerResponse { session_id }))
        } else {
            println!(" Wrong Challenge Solution username: {:?}", user_name);

            Err(Status::new(
                Code::PermissionDenied,
                format!("AuthId: {} bad solution to the challenge", auth_id),
            ))
        }
    } else {
        Err(Status::new(
            Code::NotFound,
            format!("AuthId: {} not found in database", auth_id),
        ))
    }
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

