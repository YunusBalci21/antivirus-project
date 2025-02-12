#include "MainWindow.h"
#include <QPushButton>
#include <QFileDialog>
#include <QMessageBox>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
}

MainWindow::~MainWindow() {}

void MainWindow::setupUI() {
    auto *layout = new QVBoxLayout;

    auto *scanFileBtn = new QPushButton("Scan File");
    connect(scanFileBtn, &QPushButton::clicked, this, &MainWindow::onScanFile);
    layout->addWidget(scanFileBtn);

    auto *scanDirBtn = new QPushButton("Scan Directory");
    connect(scanDirBtn, &QPushButton::clicked, this, &MainWindow::onScanDirectory);
    layout->addWidget(scanDirBtn);

    auto *widget = new QWidget;
    widget->setLayout(layout);
    setCentralWidget(widget);
}

void MainWindow::onScanFile() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Scan");
    if (!filePath.isEmpty()) {
        QMessageBox::information(this, "Scan Result", "No threats found.");
        // Call FileScanner logic here
    }
}

void MainWindow::onScanDirectory() {
    QString dirPath = QFileDialog::getExistingDirectory(this, "Select Directory to Scan");
    if (!dirPath.isEmpty()) {
        QMessageBox::information(this, "Scan Result", "Threats found!");
        // Call Directory Scanner logic here
    }
}
