Assignment 1 - REST API Project - Response to Criteria
- **Name:** Herman Van Zyl
- **Student number:** n119579438
•	Application name: Image Filtering API
•	Two line description: This REST API provides image filtering capabilities with user authentication. Users can apply various filters to single or multiple images and retain their processed images.
Core criteria
________________________________________
Containerise the app
•	ECR Repository name: n11957948-herman-repo
•	Video timestamp: 0:00
•	Relevant files:
o	Dockerfile (mentioned in transcript)
Deploy the container
•	EC2 instance ID: i-0bd0a89db4f1e171b
•	Video timestamp: 0:27
User login
•	One line description: JWT-based authentication with hard-coded user credentials
•	Video timestamp: 1:20
•	Relevant files: app.py
REST API
•	One line description: RESTful API with endpoints for authentication, image processing, and user management
•	Video timestamp: 1:20
•	Relevant files: app.py
Data types
•	One line description: The application handles both structured and unstructured data types
•	Video timestamp: 2:42
•	Relevant files:
o	app.py
First kind
•	One line description: Binary image data and processed image bytes
•	Type: Unstructured
•	Rationale: Image files are binary data that don't require structured querying
•	Video timestamp: 2:35
•	Relevant files:
o	app.py
Second kind
•	One line description: User sessions and image metadata through JWT tokens
•	Type: Structured
•	Rationale: User authentication and image metadata require structured data for validation and retrieval
•	Video timestamp: 2:42
•	Relevant files:
o	app.py
CPU intensive task
•	One line description: Image filtering operations using PIL library with configurable strength and size multipliers
•	Video timestamp: 1:30
•	Relevant files:
o	app.pyCPU load testing
•	One line description: Python script to generate concurrent requests to image filtering endpoints
•	Video timestamp: 3:10
•	Relevant files:
o	load_test.py 



Additional criteria
________________________________________
Extensive REST API features
•	One line description: Proper HTTP status codes, JWT auth headers, multipart form data for file uploads and token based authentication for protected endpoints 
•	Video timestamp: 2:45
•	Relevant files: app.py
-
External API(s)
•	One line description: Not attempted
•	Video timestamp:
•	Relevant files:
-
Additional types of data
•	One line description: Various image formats, base64 encoding/decoding, in memory binary storage, JSON API responses and metadata as well as form data for file uploads
•	Video timestamp: 2:40
•	Relevant files: app.py
-
Custom processing
•	One line description: Multiple image filters with adjustable strength and size parameters
•	Video timestamp: 1:38
•	Relevant files:
o	app.py
Infrastructure as code
•	One line description: Not attempted
•	Video timestamp:
•	Relevant files:
-
Web client
•	One line description: Interactive web interface for testing API endpoints with live previews
•	Video timestamp: 0:51
•	Relevant files:
o	index.html 
o	style.css 
Upon request
•	One line description: Not attempted
•	Video timestamp:
•	Relevant files:


