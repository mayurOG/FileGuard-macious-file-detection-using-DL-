#!/bin/bash
#
# FileGuard Quick Start Script
# Author: Mayur Nhavalde
# Description: Automated setup for FileGuard deployment
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

check_requirements() {
    print_header "Checking Requirements"
    
    # Check Docker
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version)
        print_success "Docker: $DOCKER_VERSION"
    else
        print_error "Docker not found. Please install Docker."
        exit 1
    fi
    
    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(docker-compose --version)
        print_success "Docker Compose: $COMPOSE_VERSION"
    else
        print_error "Docker Compose not found. Please install Docker Compose."
        exit 1
    fi
    
    # Check Git
    if command -v git &> /dev/null; then
        GIT_VERSION=$(git --version)
        print_success "Git: $GIT_VERSION"
    else
        print_error "Git not found. Please install Git."
        exit 1
    fi
}

setup_environment() {
    print_header "Setting Up Environment"
    
    if [ ! -f .env ]; then
        print_info "Creating .env file from template..."
        cp .env.example .env
        
        # Generate secure random keys
        SECRET_KEY=$(openssl rand -hex 32)
        DB_PASSWORD=$(openssl rand -hex 16)
        
        # Update .env
        sed -i.bak "s/change-this-in-production/$SECRET_KEY/" .env
        sed -i.bak "s/secure_password_change_me/$DB_PASSWORD/" .env
        
        print_success ".env file created with secure keys"
    else
        print_info ".env file already exists"
    fi
}

create_directories() {
    print_header "Creating Directories"
    
    mkdir -p ssl
    mkdir -p logs
    mkdir -p data
    
    print_success "Directories created"
}

build_images() {
    print_header "Building Docker Images"
    
    docker-compose build --no-cache
    print_success "Images built successfully"
}

start_services() {
    print_header "Starting Services"
    
    docker-compose up -d
    print_success "Services started"
    
    # Wait for services to be ready
    print_info "Waiting for services to be ready..."
    sleep 10
}

initialize_database() {
    print_header "Initializing Database"
    
    docker-compose exec -T fastapi python -c "
from database import init_db
init_db()
print('Database initialized successfully!')
"
    
    print_success "Database initialized"
}

verify_services() {
    print_header "Verifying Services"
    
    # Check API
    if curl -s http://localhost:8000/health > /dev/null; then
        print_success "API is running (http://localhost:8000)"
    else
        print_error "API is not responding"
    fi
    
    # Check UI
    if curl -s http://localhost:8501/_stcore/health > /dev/null; then
        print_success "UI is running (http://localhost:8501)"
    else
        print_error "UI is not responding"
    fi
}

print_summary() {
    print_header "Setup Complete!"
    
    echo -e "\n${GREEN}FileGuard is ready to use!${NC}\n"
    
    echo "Access the services:"
    echo -e "  ${BLUE}UI:${NC}         http://localhost:8501"
    echo -e "  ${BLUE}API:${NC}        http://localhost:8000"
    echo -e "  ${BLUE}Docs:${NC}       http://localhost:8000/docs"
    echo -e "  ${BLUE}ReDoc:${NC}      http://localhost:8000/redoc"
    
    echo -e "\n${YELLOW}Next steps:${NC}"
    echo "  1. Register a user at http://localhost:8501"
    echo "  2. Upload a PE file to test the system"
    echo "  3. View scan history and analytics"
    
    echo -e "\n${YELLOW}Useful commands:${NC}"
    echo "  docker-compose logs -f fastapi   # View API logs"
    echo "  docker-compose logs -f ui        # View UI logs"
    echo "  docker-compose down              # Stop all services"
    
    echo -e "\n${YELLOW}Documentation:${NC}"
    echo "  - README.md: Overview and quick start"
    echo "  - docs/DEPLOYMENT.md: Deployment guide"
    echo "  - docs/ARCHITECTURE.md: System architecture"
    echo -e "\n"
}

# Main execution
main() {
    clear
    
    echo -e "\n${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║   FileGuard - Malware Detection       ║"
    echo "║   Advanced Deployment Setup            ║"
    echo "║   Author: Mayur Nhavalde              ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}\n"
    
    check_requirements
    setup_environment
    create_directories
    build_images
    start_services
    initialize_database
    verify_services
    print_summary
}

# Error handling
trap 'print_error "Setup failed!"; exit 1' ERR

# Run main
main
