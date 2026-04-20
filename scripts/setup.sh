#!/bin/bash
# NexusChain Setup Script

set -e

echo "=========================================="
echo "  NexusChain Layer 2 Setup"
echo "=========================================="
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p circuits
mkdir -p proof_cache
mkdir -p data

# Compile circuits (placeholder)
echo "Compiling ZK circuits..."
python3 -c "from src.zk_rollup.circuit import compile_circuits; compile_circuits('./circuits')" || true

# Initialize git hooks (if git is initialized)
if [ -d ".git" ]; then
    echo "Setting up git hooks..."
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
black --check src/
flake8 src/
mypy src/
EOF
    chmod +x .git/hooks/pre-commit
fi

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "To activate the environment:"
echo "  source venv/bin/activate"
echo ""
echo "To start the sequencer:"
echo "  python -m src.sequencer.main"
echo ""
echo "To start the prover:"
echo "  python -m src.prover.main"
echo ""
echo "To start the RPC server:"
echo "  python -m src.rpc.main"
echo ""
