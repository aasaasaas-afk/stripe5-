# Use the official Python slim image for a smaller footprint
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY app.py .

# Expose the port Render expects (default is 10000 for Render)
EXPOSE 10000

# Command to run the Flask app
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]
