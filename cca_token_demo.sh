#!/bin/bash

# CCA Token Demo Script
# This script demonstrates common operations with the ccatoken CLI tool

set -e  # Exit on any error
set -u  # Treat unset variables as errors

# Define colors for better output formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}=========================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=========================================================${NC}\n"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}✗ $1${NC}"
    return 1
}

# Function to print info messages
print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Make sure we're in the project directory
cd "$(dirname "$0")"

# Check if the ccatoken binary exists and is in the PATH
check_ccatoken() {
    print_header "Checking ccatoken binary"
    
    if ! command -v ccatoken &> /dev/null; then
        print_info "Building ccatoken binary"
        cargo build || print_error "Failed to build ccatoken"
        export PATH=$PATH:"$PWD/target/debug"
    fi
    
    if command -v ccatoken &> /dev/null; then
        print_success "ccatoken binary found in PATH"
    else
        print_error "ccatoken binary not found in PATH. Make sure to build the project first."
    fi
}

# Verify a CCA token using trust anchors
verify_token() {
    print_header "Verifying CCA Token"
    
    local token_file="$1"
    local tastore_file="$2"
    
    print_info "Verifying token: $token_file with trust anchor store: $tastore_file"
    
    if ccatoken verify -e "$token_file" -t "$tastore_file"; then
        print_success "Token verification successful"
    else
        print_error "Token verification failed"
    fi
}

# Appraise a CCA token using reference values
appraise_token() {
    print_header "Appraising CCA Token"
    
    local token_file="$1"
    local rvstore_file="$2"
    
    print_info "Appraising token: $token_file with reference value store: $rvstore_file"
    
    if ccatoken appraise -e "$token_file" -r "$rvstore_file"; then
        print_success "Token appraisal successful"
    else
        print_error "Token appraisal failed"
    fi
}

# Extract golden values from a CCA token
extract_golden_values() {
    print_header "Extracting Golden Values"
    
    local token_file="$1"
    local cpak_file="$2"
    local tastore_output="golden-tastore.json"
    local rvstore_output="golden-rvstore.json"
    
    print_info "Extracting golden values from token: $token_file with CPAK: $cpak_file"
    
    if ccatoken golden -e "$token_file" -c "$cpak_file" -t "$tastore_output" -r "$rvstore_output"; then
        print_success "Golden values extraction successful"
        print_info "Trust anchors saved to: $tastore_output"
        print_info "Reference values saved to: $rvstore_output"
        
        # Pretty print the golden values (if jq is available)
        if command -v jq &> /dev/null; then
            echo -e "\n${YELLOW}Trust Anchor Store Content:${NC}"
            jq . "$tastore_output"
            
            echo -e "\n${YELLOW}Reference Value Store Content:${NC}"
            jq . "$rvstore_output"
        fi
    else
        print_error "Golden values extraction failed"
    fi
}

# List available test tokens
list_test_tokens() {
    print_header "Available Test Tokens"
    
    echo "CBOR Test Tokens:"
    find testdata -name "*.cbor" | sort
    
    echo -e "\nDiagnostic Format Tokens:"
    find testdata -name "*.diag" | sort
}

# Main function
main() {
    # Check if ccatoken binary is available
    check_ccatoken
    
    # Example usage with test data
    print_header "CCA Token Demo"
    
    # List available test tokens
    list_test_tokens
    
    # Default test files
    local default_token="testdata/cca-token-01.cbor"
    local default_cpak="testdata/cpak.json"
    local default_tastore="testdata/ta.json"
    local default_rvstore="testdata/rv.json"
    
    # Run verification with default test files
    verify_token "$default_token" "$default_tastore"
    
    # Run appraisal with default test files
    appraise_token "$default_token" "$default_rvstore"
    
    # Extract golden values with default test files
    extract_golden_values "$default_token" "$default_cpak"
    
    print_header "Demo completed successfully!"
}

# Run the main function
main