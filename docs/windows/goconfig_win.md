# Installing Go properly on Windows

You can download Go from the [Go website] (click on the Windows tab), and then 
running the installer.
However, unfortunately this isn't it. To install Go properly on Windows, the 
environment variables need to be configured properly:

## Configuring environment variables

1. Open the **System Properties** dialog by pressing `Win + R` and typing 
    `SystemPropertiesAdvanced`.
2. Open the **Environment Variables** dialog by pressing the 
   `Environment Variables` button in the bottom right corner.
3. `GOPATH` may already be configured automatically as `C:\Users\{user}\go`. <br>
4. Set the value `GOROOT` variable
   1. Click on the `New` button in `User variables for {user}`
   2. Enter `GOROOT` in the "Variable name" field
   3. Enter the location of your Go installation in the "Variable value" field.<br>
      This will most likely be `C:\Program Files\Go`  
4. Open the `PATH` variable, and add the same value as in `GOROOT`.
   1. To do this, double-click the variable named `PATH`.
   2. Click on the `New` button in the top right corner and add the same value 
      as in `GOROOT`.
6. Click on all `OK` buttons to save and exit.

[Go website]: https://go.dev/doc/install
