add_vpp_plugin(radius
  SOURCES
  radius.c
  radius_api.c
  radius_cli.c
  radius_codec.c
  radius_md5.c
  radius_pending.c
  radius_transport.c
  radius_input.c

  API_FILES
  radius.api

  INSTALL_HEADERS
  radius_service.h
)
