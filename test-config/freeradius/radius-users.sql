-- FreeRADIUS SQL тестовые данные
-- Совместимо с MySQL, MariaDB, PostgreSQL
-- Применить: mysql -u radius -p radius < radius-users.sql
--         или psql -U radius radius < radius-users.sql

-- ═══════════════════════════════════════════════════════════════════════════
-- Создание таблиц (если не существуют)
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS radcheck (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username   VARCHAR(64)  NOT NULL DEFAULT '',
  attribute  VARCHAR(64)  NOT NULL DEFAULT '',
  op         CHAR(2)      NOT NULL DEFAULT ':=',
  value      VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  INDEX idx_username (username(32))
);

CREATE TABLE IF NOT EXISTS radreply (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username   VARCHAR(64)  NOT NULL DEFAULT '',
  attribute  VARCHAR(64)  NOT NULL DEFAULT '',
  op         CHAR(2)      NOT NULL DEFAULT '=',
  value      VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  INDEX idx_username (username(32))
);

CREATE TABLE IF NOT EXISTS radgroupcheck (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  groupname  VARCHAR(64)  NOT NULL DEFAULT '',
  attribute  VARCHAR(64)  NOT NULL DEFAULT '',
  op         CHAR(2)      NOT NULL DEFAULT ':=',
  value      VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  INDEX idx_groupname (groupname(32))
);

CREATE TABLE IF NOT EXISTS radgroupreply (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  groupname  VARCHAR(64)  NOT NULL DEFAULT '',
  attribute  VARCHAR(64)  NOT NULL DEFAULT '',
  op         CHAR(2)      NOT NULL DEFAULT '=',
  value      VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  INDEX idx_groupname (groupname(32))
);

CREATE TABLE IF NOT EXISTS radusergroup (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username   VARCHAR(64)  NOT NULL DEFAULT '',
  groupname  VARCHAR(64)  NOT NULL DEFAULT '',
  priority   INT          NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  INDEX idx_username (username(32))
);

-- ═══════════════════════════════════════════════════════════════════════════
-- Очистка тестовых данных (безопасно повторять)
-- ═══════════════════════════════════════════════════════════════════════════

DELETE FROM radcheck      WHERE username  IN ('alice','bob','charlie','diana','eve','frank','guest');
DELETE FROM radreply      WHERE username  IN ('alice','bob','charlie','diana','eve','frank','guest');
DELETE FROM radusergroup  WHERE username  IN ('alice','bob','charlie','diana','eve','frank','guest');
DELETE FROM radgroupcheck WHERE groupname IN ('vpn-full','vpn-split','vpn-restricted','vpn-admin','vpn-disabled');
DELETE FROM radgroupreply WHERE groupname IN ('vpn-full','vpn-split','vpn-restricted','vpn-admin','vpn-disabled');

-- ═══════════════════════════════════════════════════════════════════════════
-- Группы: radgroupcheck (условия для входа в группу)
-- ═══════════════════════════════════════════════════════════════════════════

-- vpn-full: принять без дополнительных условий
INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES
  ('vpn-full',       'Auth-Type', ':=', 'Accept');

-- vpn-split: принять
INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES
  ('vpn-split',      'Auth-Type', ':=', 'Accept');

-- vpn-restricted: принять + ограничение по времени сессии
INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES
  ('vpn-restricted', 'Auth-Type', ':=', 'Accept');

-- vpn-admin: принять
INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES
  ('vpn-admin',      'Auth-Type', ':=', 'Accept');

-- vpn-disabled: явно отклонять
INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES
  ('vpn-disabled',   'Auth-Type', ':=', 'Reject');

-- ═══════════════════════════════════════════════════════════════════════════
-- Группы: radgroupreply (атрибуты, которые получает пользователь группы)
-- Filter-Id используется radius-agent для определения VPN-профиля
-- ═══════════════════════════════════════════════════════════════════════════

-- vpn-full → full-tunnel через весь трафик
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
  ('vpn-full', 'Filter-Id',       '=',  'vpn-full'),
  ('vpn-full', 'Session-Timeout', '=',  '86400'),
  ('vpn-full', 'Idle-Timeout',    '=',  '7200'),
  ('vpn-full', 'Reply-Message',   '=',  'VPN full-tunnel access granted');

-- vpn-split → split-tunnel, только внутренняя сеть
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
  ('vpn-split', 'Filter-Id',       '=',  'vpn-split'),
  ('vpn-split', 'Session-Timeout', '=',  '28800'),
  ('vpn-split', 'Idle-Timeout',    '=',  '3600'),
  ('vpn-split', 'Reply-Message',   '=',  'VPN split-tunnel (internal) access granted');

-- vpn-restricted → только 192.17.0.5
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
  ('vpn-restricted', 'Filter-Id',       '=',  'vpn-restricted'),
  ('vpn-restricted', 'Session-Timeout', '=',  '14400'),
  ('vpn-restricted', 'Idle-Timeout',    '=',  '1800'),
  ('vpn-restricted', 'Reply-Message',   '=',  'Restricted host access only');

-- vpn-admin → full-tunnel + расширенный таймаут
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
  ('vpn-admin', 'Filter-Id',       '=',  'vpn-admin'),
  ('vpn-admin', 'Session-Timeout', '=',  '0'),
  ('vpn-admin', 'Idle-Timeout',    '=',  '0'),
  ('vpn-admin', 'Reply-Message',   '=',  'Admin VPN access granted');

-- vpn-disabled → сообщение об отказе
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
  ('vpn-disabled', 'Reply-Message', '=', 'Account is disabled');

-- ═══════════════════════════════════════════════════════════════════════════
-- Пользователи: radcheck (проверка пароля)
-- ═══════════════════════════════════════════════════════════════════════════

INSERT INTO radcheck (username, attribute, op, value) VALUES
  -- alice: full-tunnel
  ('alice',   'Cleartext-Password', ':=', 'alice-pass-2024'),
  -- bob: split-tunnel
  ('bob',     'Cleartext-Password', ':=', 'bob-pass-2024'),
  -- charlie: только 192.17.0.5
  ('charlie', 'Cleartext-Password', ':=', 'charlie-pass-2024'),
  -- diana: admin
  ('diana',   'Cleartext-Password', ':=', 'diana-pass-2024'),
  -- eve: заблокирован (Auth-Type Reject переопределяет группу)
  ('eve',     'Auth-Type',          ':=', 'Reject'),
  -- frank: split-tunnel, 8ч сессия
  ('frank',   'Cleartext-Password', ':=', 'frank-pass-2024'),
  -- guest: временный доступ, restricted
  ('guest',   'Cleartext-Password', ':=', 'guest-temp-2024');

-- ═══════════════════════════════════════════════════════════════════════════
-- Пользователи: radreply (индивидуальные атрибуты, дополняют группу)
-- ═══════════════════════════════════════════════════════════════════════════

INSERT INTO radreply (username, attribute, op, value) VALUES
  -- guest: ограничение 1ч сессии (переопределяет групповое значение)
  ('guest',  'Session-Timeout', ':=', '3600'),
  -- frank: явное имя для логов
  ('frank',  'Reply-Message',   '+=', ' (frank@corp.example.com)');

-- ═══════════════════════════════════════════════════════════════════════════
-- Привязка пользователей к группам: radusergroup
-- Меньший priority = выше приоритет группы
-- ═══════════════════════════════════════════════════════════════════════════

INSERT INTO radusergroup (username, groupname, priority) VALUES
  ('alice',   'vpn-full',       1),
  ('bob',     'vpn-split',      1),
  ('charlie', 'vpn-restricted', 1),
  ('diana',   'vpn-admin',      1),
  ('diana',   'vpn-full',       2),  -- diana: и admin, и full (admin приоритетнее)
  ('eve',     'vpn-disabled',   1),
  ('frank',   'vpn-split',      1),
  ('guest',   'vpn-restricted', 1);

-- ═══════════════════════════════════════════════════════════════════════════
-- Проверка
-- ═══════════════════════════════════════════════════════════════════════════
SELECT
  u.username,
  GROUP_CONCAT(g.groupname ORDER BY g.priority SEPARATOR ', ') AS groups,
  IFNULL(r.value, '(пароль в radcheck)') AS note
FROM radusergroup g
JOIN radcheck u ON u.username = g.username AND u.attribute = 'Cleartext-Password'
LEFT JOIN radreply r ON r.username = g.username AND r.attribute = 'Reply-Message'
GROUP BY u.username, r.value
ORDER BY u.username;
