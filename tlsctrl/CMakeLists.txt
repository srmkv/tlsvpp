find_package(OpenSSL REQUIRED)

add_vpp_plugin(tlsctrl
  SOURCES
  tlsctrl.c
  tlsctrl_cli.c
  tlsctrl_app.c
  tlsctrl_api.c
  tlsctrl_vpn.c
  tlsctrl_vpn_api.c
  tlsctrl_vpn_cli.c
  tlsctrl_vpn_dp.c
  tlsctrl_vpn_dp_cli.c
  tlsctrl_vpn_frame.c
  tlsctrl_vpn_frame_cli.c
  tlsctrl_vpn_transport_cli.c
  tlsctrl_vpn_transport.c
  tlsctrl_vpn_stream.c
  tlsctrl_vpn_stream_cli.c

  API_FILES
  tlsctrl.api
  tlsctrl_vpn.api

  INSTALL_HEADERS
  tlsctrl.h
  tlsctrl_vpn.h
)

if(TARGET tlsctrl_plugin)
  if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
    target_link_libraries(tlsctrl_plugin OpenSSL::SSL OpenSSL::Crypto)
  elseif(OPENSSL_SSL_LIBRARY AND OPENSSL_CRYPTO_LIBRARY)
    target_link_libraries(tlsctrl_plugin ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
  else()
    target_link_libraries(tlsctrl_plugin ssl crypto)
  endif()
endif()
