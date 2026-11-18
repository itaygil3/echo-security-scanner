-- Seed the 10 images required by the assignment. Idempotent.
INSERT INTO images (name, tag, scan_status) VALUES
    ('nginx',    '1.19',      'PENDING'),
    ('postgres', '12',        'PENDING'),
    ('redis',    '6.0',       'PENDING'),
    ('node',     '14-alpine', 'PENDING'),
    ('python',   '3.8-slim',  'PENDING'),
    ('alpine',   '3.12',      'PENDING'),
    ('ubuntu',   '20.04',     'PENDING'),
    ('mysql',    '8.0',       'PENDING'),
    ('mongo',    '4.4',       'PENDING'),
    ('httpd',    '2.4',       'PENDING')
ON CONFLICT (name, tag) DO NOTHING;
