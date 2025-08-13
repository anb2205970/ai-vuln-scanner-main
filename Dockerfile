FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    nmap \
    perl \
    git \
    libnet-ssleay-perl \
    openssl \
    libio-socket-ssl-perl \
 && git clone https://github.com/sullo/nikto.git /opt/nikto \
 && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir streamlit>=1.28.0 requests>=2.31.0 lxml>=4.9.0

# Expose Streamlit port
EXPOSE 8501

# Run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
