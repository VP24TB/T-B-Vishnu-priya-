CREATE DATABASE IF NOT EXISTS ecommerce_fraud_db;
USE ecommerce_fraud_db;
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total_amount DECIMAL(10,2) NOT NULL,
    order_status ENUM('Pending', 'Completed', 'Cancelled') DEFAULT 'Pending',
    ip_address VARCHAR(50),
    billing_address VARCHAR(255),
    shipping_address VARCHAR(255),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE fraud_logs (
    fraud_id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT,
    user_id INT,
    fraud_reason VARCHAR(255),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(order_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Step 3: Fraud Detection Triggers
DELIMITER //
CREATE TRIGGER detect_fraud
AFTER INSERT ON orders
FOR EACH ROW
BEGIN
    -- Rule 1: High-value transaction from a new user
    IF (NEW.total_amount > 500 AND (SELECT TIMESTAMPDIFF(DAY, created_at, NOW()) FROM users WHERE user_id = NEW.user_id) < 30) THEN
        INSERT INTO fraud_logs (order_id, user_id, fraud_reason)
        VALUES (NEW.order_id, NEW.user_id, 'High-value transaction from a new user');
    END IF;
    
    -- Rule 2: Multiple orders from the same IP within a short period
    IF ((SELECT COUNT(*) FROM orders WHERE ip_address = NEW.ip_address AND order_date > NOW() - INTERVAL 1 HOUR) > 3) THEN
        INSERT INTO fraud_logs (order_id, user_id, fraud_reason)
        VALUES (NEW.order_id, NEW.user_id, 'Multiple orders from the same IP in a short time');
    END IF;
    
    -- Rule 3: Mismatched billing and shipping addresses
    IF (NEW.billing_address != NEW.shipping_address) THEN
        INSERT INTO fraud_logs (order_id, user_id, fraud_reason)
        VALUES (NEW.order_id, NEW.user_id, 'Billing and shipping addresses do not match');
    END IF;
END //
DELIMITER ;

-- Step 4: Query to View Suspicious Transactions
SELECT * FROM fraud_logs ORDER BY detected_at DESC;
