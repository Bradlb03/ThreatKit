    # Use an official Python runtime as a parent image
    FROM python:3.9-slim-buster

    # Set the working directory in the container
    WORKDIR /app

    # Copy the requirements file and install dependencies
    COPY requirements.txt requirements.txt
    RUN pip install -r requirements.txt

    # Copy the rest of the application code
    COPY . .

    # Expose the port your Flask app runs on
    EXPOSE 5000

    # Define the command to run your Flask application
    CMD ["python", "app.py"]