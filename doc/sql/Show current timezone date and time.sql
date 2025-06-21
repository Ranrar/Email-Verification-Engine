SELECT
  current_setting('timezone') AS "Current Timezone",
  to_char(now(), 'YYYY-MM-DD') AS "Current Date",
  to_char(now(), 'HH24:MI:SS TZ') AS "Current Time";