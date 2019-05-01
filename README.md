# BurpHttpMock

This Burp extension provides mock responses based on the real ones. 

Create a mock by selecting entry from HTTP History or craft it manually. Requests are matched by customizable regex rules and forwarded to the local mock server. Mocks can have various behavior, including directly entering the input, reading replies from a file, redirecting to a different URL, or calling another process and returning the output.

Using this extension it is possible to test how web frontend and mobile clients react to different responses, without making any changes to the backend.
It differs from intercepting responses mainly in two ways: 
- the original request is not sent to the server anymore;
- it provides a more convenient and comprehensive solution to modifying responses.

## Screenshots/Demo

The media in this section are from an older version, but still demonstrate the core functionality.

[Demo](https://drive.google.com/file/d/1jypD6-CnpSv25IVnMFt-o3rnljbMqsAv)

![screen 3](https://raw.githubusercontent.com/LogicalTrust/materials/master/burp-httpmock/1.png)
![screen 1](https://raw.githubusercontent.com/LogicalTrust/materials/master/burp-httpmock/2.png)

## Building

This project targets Java 8 to match Burp's current supported Java version. Building the project requires [Maven](https://maven.apache.org). To build the project, simply run `mvn package`.