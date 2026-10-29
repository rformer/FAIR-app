-- F-001 T-27 (AC-53): a custom role whose separation-of-duties exception has
-- expired is suspended (it grants nothing until fixed). A new enum value is
-- usable only after its migration commits, so it has a file of its own.

ALTER TYPE iam.role_status ADD VALUE IF NOT EXISTS 'suspended';
