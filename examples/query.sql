SELECT
  o.id,
  o.created_at,
  c.email,
  SUM(oi.quantity * oi.unit_price) AS total_amount
FROM orders o
JOIN customers c ON c.id = o.customer_id
JOIN order_items oi ON oi.order_id = o.id
WHERE o.created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY o.id, o.created_at, c.email
ORDER BY total_amount DESC
LIMIT 100;
