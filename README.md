Overview

This repository contains the code and infrastructure files for a project that implements a cloud-based image processing system. The project demonstrates the use of AWS services, microservices architecture, autoscaling, security tools, and infrastructure-as-code principles.

Users can upload images through a web interface, apply filters (blur, sharpen, emboss), and view the processed results. The focus of the project is on demonstrating distributed design, scalability, and cloud service integration rather than building a production application.

Project Components

1. Web/API Service

The main EC2-hosted service provides user registration and login using AWS Cognito, image upload and retrieval and basic web interface for interacting with the system

Key files:

app.py

cognito_helper.py

s3_helper.py

dynamodb_helper.py


2. Image Processing Service

A separate EC2 instance runs the image-processing microservice. It receives tasks, applies filters, and saves the processed images back to S3.


Architecture Summary

The system is split into independent web and processing components. Traffic is routed through an Application Load Balancer. Autoscaling is enabled for the web and processing services based on CPU utilisation. Cognito handles user authentication. CloudWatch is used for monitoring and logging. The goal of the architecture is to meet the requirements of the assignment (microservices, scaling mechanisms, security, IaC, etc.) rather than creating a commercial product.

How the System Works

A user signs in via Cognito. An image is uploaded through the web interface. The image is stored in S3 and metadata is written to DynamoDB. The processing instance retrieves the image and applies the selected filter. The processed version is saved back to S3 and displayed to the user.




It is not intended for commercial deployment.
