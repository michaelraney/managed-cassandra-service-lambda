package com.aws.ssa.mcs;


import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.datastax.driver.core.*;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class MCSLambdaConnectionExample implements RequestHandler<Object, String> {

    private Session session;

    public MCSLambdaConnectionExample(){
        session = getSession();
    }

    @Override
    public String handleRequest(Object input, Context context)  {
        context.getLogger().log("Input: " + input);

        getSession().execute("CREATE KEYSPACE IF NOT EXISTS mykeyspace WITH replication = {'class': 'SingleRegionStrategy'}");

        return "Finish";
    }

    //Singleton pattern.
    //Connection session is thread safe and can be reused
    private Session getSession(){
        if(session == null){
            session = connectToAWSManagedCassandraService();
        }
        return session;
    }

    private synchronized Session connectToAWSManagedCassandraService(){

        if(session == null) {
            System.out.println("Initialize Connection");

            try {

                loadManagedCassandraCert();

                //https://docs.aws.amazon.com/secretsmanager/latest/userguide/tutorials_basic.html
                Map<String, String> secretMap = getMCSCredentialsFromSecretManager();

                String user = secretMap.get("username");
                String password = secretMap.get("password");

                Cluster cluster = Cluster.builder()
                        .addContactPoint("cassandra.us-east-1.amazonaws.com")
                        .withSSL()
                        .withPort(9142)
                        .withAuthProvider(new PlainTextAuthProvider(user, password))
                        .build();

                session = cluster.connect();
                // context.getLogger().log("Connection successful...");
            }catch (Exception ex){
                ex.printStackTrace();
            }

        }
        return session;
    }

    // load SSL Cert to truststore
    private void loadManagedCassandraCert() throws Exception {

        //locate the default truststore
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (FileInputStream fis = new FileInputStream(filename)) {

            keystore.load(fis, "changeit".toCharArray());

        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        //Input stream to cert file
        Certificate caCert = cf.generateCertificate(getPemFile());// IOUtils.toInputStream(CA_CERT));
        keystore.setCertificateEntry("ca-cert", caCert);

        //can only save to /tmp from a lambda
        String certPath = "/tmp/CustomTruststore";

        String trustStorePassword = "amazon";

        try (FileOutputStream out = new FileOutputStream(certPath)) {

            keystore.store(out, trustStorePassword.toCharArray());
        }

        System.setProperty("javax.net.ssl.trustStore", certPath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
    }
    //TODO:Retrieve PEM From S3 or Secret Manager
    private FileInputStream getPemFile() throws Exception{
        ClassLoader classLoader = getClass().getClassLoader();

        File cityFile = new File(classLoader.getResource("AmazonRootCA1.pem").getFile());

        FileInputStream fis;

        fis = new FileInputStream(cityFile.getPath());

        return fis;

    }

    // Get Secret from manager
    // If you need more information about configurations or implementing the sample code, visit the AWS docs:
    // https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/java-dg-samples.html#prerequisites
    public static Map<String,String> getMCSCredentialsFromSecretManager() throws Exception{

        String secretName = "mcsCredentials";
        String region = System.getenv("AWS_REGION");

        // Create a Secrets Manager client
        AWSSecretsManager client  = AWSSecretsManagerClientBuilder.standard()
                .withRegion(region)
                .build();

        // In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
        // See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        // We rethrow the exception by default.

        String secret, decodedBinarySecret;
        GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                .withSecretId(secretName);
        GetSecretValueResult getSecretValueResult = client.getSecretValue(getSecretValueRequest);


        HashMap<String,String> userPass;
        // Decrypts secret using the associated KMS CMK.
        // Depending on whether the secret is a string or binary, one of these fields will be populated.
        if (getSecretValueResult.getSecretString() != null) {
            secret = getSecretValueResult.getSecretString();
            userPass = new ObjectMapper().readValue(secret, HashMap.class);
        }
        else {
            decodedBinarySecret = new String(Base64.getDecoder().decode(getSecretValueResult.getSecretBinary()).array());
            userPass = new ObjectMapper().readValue(decodedBinarySecret, HashMap.class);
        }

        return userPass;
    }
}
