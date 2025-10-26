#!/bin/bash

# GitHub Setup Script for A-CLAT
# Developed by clevernat

echo "================================================"
echo "  A-CLAT GitHub Repository Setup"
echo "  Developed by clevernat"
echo "================================================"
echo ""

# Repository details
REPO_NAME="AI-Assisted-Convective-Cell-Annotator"
REPO_DESCRIPTION="Advanced atmospheric analysis application with AI-powered storm classification and tracking"
USERNAME="clevernat"

echo "This script will help you push the A-CLAT project to GitHub."
echo ""
echo "Repository Details:"
echo "  Name: $REPO_NAME"
echo "  Description: $REPO_DESCRIPTION"
echo "  URL: https://github.com/$USERNAME/$REPO_NAME"
echo ""
echo "================================================"
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git add .
    git commit -m "Initial commit: A-CLAT v2.0 by clevernat"
fi

echo "Step 1: Create a new repository on GitHub"
echo "----------------------------------------"
echo "1. Go to: https://github.com/new"
echo "2. Repository name: $REPO_NAME"
echo "3. Description: $REPO_DESCRIPTION"
echo "4. Set to Public"
echo "5. DON'T initialize with README, .gitignore, or license"
echo "6. Click 'Create repository'"
echo ""
read -p "Press Enter when you've created the repository..."

echo ""
echo "Step 2: Push to GitHub"
echo "----------------------"
echo "Run these commands:"
echo ""
echo "git remote add origin https://github.com/$USERNAME/$REPO_NAME.git"
echo "git branch -M main"
echo "git push -u origin main"
echo ""
echo "Or if you prefer SSH:"
echo "git remote add origin git@github.com:$USERNAME/$REPO_NAME.git"
echo "git branch -M main"
echo "git push -u origin main"
echo ""

# Optionally set the remote
read -p "Would you like to set the remote now? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Setting up remote..."
    git remote add origin https://github.com/$USERNAME/$REPO_NAME.git 2>/dev/null || git remote set-url origin https://github.com/$USERNAME/$REPO_NAME.git
    git branch -M main
    echo "Remote configured!"
    echo ""
    echo "Now run: git push -u origin main"
    echo "You'll be prompted for your GitHub username and password/token."
fi

echo ""
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "After pushing, your project will be available at:"
echo "https://github.com/$USERNAME/$REPO_NAME"
echo ""
echo "Don't forget to:"
echo "1. Add topics: weather, atmospheric-science, ai, storm-tracking"
echo "2. Update the About section with the description"
echo "3. Consider adding a live demo link when deployed"
echo ""