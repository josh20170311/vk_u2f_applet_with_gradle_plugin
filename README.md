# vk_u2f_gradle
add gradle plugin into fido u2f applet from [vk_u2f](https://github.com/VivoKey/vk-u2f)

## applet install
1. download vku2f
2. use intelliJ to open the project
3. build javacard
4. install applet by cmd
    1. open cmd by admin
    1. change directory to the location of cap file
    1. gp --install applet.cap
5. put certificate
    1. copy the command in the cert.txt
    1. run the command
