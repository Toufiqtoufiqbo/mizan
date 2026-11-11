import pathlib

import pgserver

print("pgserver ok")
srv = pgserver.get_server(pgdata=pathlib.Path("C:/Users/Rahim/AppData/Local/Temp/pgdata-mizan"), cleanup_mode=None)
print("uri:", srv.get_uri())
print("version:", srv.psql("SELECT version()"))
