-- 1. First, drop all views
DO $$ 
DECLARE
    view_rec RECORD;
BEGIN
    FOR view_rec IN (
        SELECT table_name 
        FROM information_schema.views 
        WHERE table_schema = current_schema()
    ) LOOP
        EXECUTE 'DROP VIEW IF EXISTS ' || quote_ident(view_rec.table_name) || ' CASCADE';
    END LOOP;
END $$;

-- 2. Drop all tables
DO $$ 
DECLARE
    table_rec RECORD;
BEGIN
    FOR table_rec IN (
        SELECT tablename 
        FROM pg_tables 
        WHERE schemaname = current_schema()
    ) LOOP
        EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(table_rec.tablename) || ' CASCADE';
    END LOOP;
END $$;

-- 3. Drop all functions
DO $$ 
DECLARE
    func_rec RECORD;
BEGIN
    FOR func_rec IN (
        SELECT ns.nspname AS schema_name, 
               p.proname AS function_name,
               pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_proc p
        INNER JOIN pg_namespace ns ON p.pronamespace = ns.oid
        WHERE ns.nspname = current_schema()
          AND p.prokind = 'f'
    ) LOOP
        EXECUTE 'DROP FUNCTION IF EXISTS ' || 
                quote_ident(func_rec.schema_name) || '.' || 
                quote_ident(func_rec.function_name) || 
                '(' || func_rec.args || ') CASCADE';
    END LOOP;
END $$;

-- 4. Drop all procedures (PostgreSQL 11+)
DO $$ 
DECLARE
    proc_rec RECORD;
BEGIN
    FOR proc_rec IN (
        SELECT ns.nspname AS schema_name, 
               p.proname AS procedure_name,
               pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_proc p
        INNER JOIN pg_namespace ns ON p.pronamespace = ns.oid
        WHERE ns.nspname = current_schema()
          AND p.prokind = 'p'
    ) LOOP
        EXECUTE 'DROP PROCEDURE IF EXISTS ' || 
                quote_ident(proc_rec.schema_name) || '.' || 
                quote_ident(proc_rec.procedure_name) || 
                '(' || proc_rec.args || ') CASCADE';
    END LOOP;
END $$;

-- 5. Drop all types
DO $$ 
DECLARE
    type_rec RECORD;
BEGIN
    FOR type_rec IN (
        SELECT typname
        FROM pg_type t
        JOIN pg_namespace n ON t.typnamespace = n.oid
        WHERE n.nspname = current_schema()
          AND t.typtype = 'c' -- composite types
          AND NOT EXISTS (
              SELECT 1 FROM pg_class c
              WHERE c.relname = t.typname AND c.relkind = 'r'
          )
    ) LOOP
        EXECUTE 'DROP TYPE IF EXISTS ' || quote_ident(type_rec.typname) || ' CASCADE';
    END LOOP;
END $$;

-- 6. Drop all sequences
DO $$ 
DECLARE
    seq_rec RECORD;
BEGIN
    FOR seq_rec IN (
        SELECT relname
        FROM pg_class
        WHERE relkind = 'S'
          AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())
    ) LOOP
        EXECUTE 'DROP SEQUENCE IF EXISTS ' || quote_ident(seq_rec.relname) || ' CASCADE';
    END LOOP;
END $$;

-- 7. Drop all indexes that might remain
DO $$ 
DECLARE
    idx_rec RECORD;
BEGIN
    FOR idx_rec IN (
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = current_schema()
    ) LOOP
        EXECUTE 'DROP INDEX IF EXISTS ' || quote_ident(idx_rec.indexname) || ' CASCADE';
    END LOOP;
END $$;