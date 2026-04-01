find_package(OpenSSL REQUIRED)

add_vpp_plugin(tlsctrl
  SOURCES
  tlsctrl.c
  tlsctrl_cli.c
  tlsctrl_app.c
  tlsctrl_api.c

  API_FILES
  tlsctrl.api

  INSTALL_HEADERS
  tlsctrl.h
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
