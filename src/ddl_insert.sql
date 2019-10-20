INSERT INTO "users" (
  "username",
  "password"
) VALUES (
  'admin',
  'P@ssw0rd'
), (
  'User 1',
  'password1'
), (
  'User 2',
  'password2'
), (
  'User 3',
  'password3'
) ON CONFLICT DO NOTHING;
