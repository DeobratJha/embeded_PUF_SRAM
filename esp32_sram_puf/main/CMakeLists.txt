idf_component_register(
    SRCS
        #"main_gcc.c"
        "main_uav.c"
        "esp_now_comm.c"
        "authentication.c"
        "puf_lib.c"
        "distance_sensor.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        nvs_flash
        esp_wifi
        esp_event
        esp_timer
        mbedtls
        esp_driver_gpio
        objective_2
)



# idf_component_register(
#     SRCS 
#         "main_uav.c"
#         "puf_lib.c"
#         "authentication.c"
#         "distance_sensor.c"
#         "esp_now_comm.c"
#      INCLUDE_DIRS
#         "."
#         "../objective_2"
#         "../objective_2/include"
#          "../objective_2/src"
#          "../objective_2/kyber_core/ref"
#     REQUIRES
#         esp_wifi
#         esp_driver_gpio
#         esp_timer
#         nvs_flash
#         mbedtls
#         objective_2
# )

# target_link_libraries(${COMPONENT_LIB} PRIVATE objective_2)

