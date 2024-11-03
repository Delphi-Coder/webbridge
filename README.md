
# WebBridge

WebBridge is a lightweight, C-based HTTP server designed for simple file sharing and directory browsing. It allows users to upload and download files, submit text, and navigate directories through a user-friendly web interface. Ideal for small-scale file transfers, educational purposes, or as a foundation for learning about network programming in C.

## Features

- **Directory Listing**: Browse directories with detailed listings, including file names, sizes, and last modified dates.
- **File Uploading**: Upload multiple files directly to the server via a web form.
- **File Downloading**: Download files by clicking on them in the directory listing.
- **Text Submission**: Submit text through a web form, which is saved to a file on the server.
- **Directory Navigation**: Navigate through directories using the web interface, with proper handling of paths to ensure security.
- **MIME Type Handling**: Serves files with appropriate `Content-Type` headers based on file extensions, ensuring correct handling by browsers.
- **Customizable Interface**: Simple HTML and CSS styling, easily customizable to suit your preferences.
- **Alternating Row Colors**: Enhanced table readability with alternating row colors in the directory listing.

## Supported File Types

Files with the following extensions are properly handled and displayed in the browser:

- **Text and HTML Files**: `.html`, `.htm`, `.txt`
- **Images**: `.jpg`, `.jpeg`, `.png`, `.gif`
- **Stylesheets**: `.css`
- **JavaScript Files**: `.js`

Other file types will prompt the browser to download the file.

## Installation

### Prerequisites

- A Unix-like operating system (Linux, macOS, etc.)
- GCC (GNU Compiler Collection) or a compatible C compiler
- Make utility

### Clone the Repository

```bash
git clone https://github.com/Delphi-Coder/Web-bridge.git
cd Web-bridge
```

### Build the Program

Compile the source code using the provided `Makefile`:

```bash
make
```

This will generate the `webbridge` executable in the project directory.

### Install the Program

To install `webbridge` to your system (default location: `/usr/local/bin`), run:

```bash
sudo make install
```

You can specify a different installation prefix if desired:

```bash
sudo make install PREFIX=/usr
```

### Uninstall the Program

To remove the installed executable from your system, run:

```bash
sudo make uninstall
```

## Usage

### Basic Usage

Run the server with default settings:

```bash
./webbridge
```

This starts the server on port `8080`, serving the current directory.

### Custom Directory and Port

Specify the directory to serve and the port number:

```bash
./webbridge [directory] [port]
```

- **`directory`**: The folder you want to share (default is the current directory).
- **`port`**: The port number to listen on (default is `8080`).

Example:

```bash
./webbridge /path/to/share 8000
```

### Displaying a Text File

You can display the content of a text file on the main page:

```bash
./webbridge [directory] [port] [text_file]
```

Example:

```bash
./webbridge . 8080 welcome.txt
```

### Accessing the Server

Open your web browser and navigate to:

```
http://localhost:8080/
```

Replace `8080` with the port number you specified if different.

## Features in Detail

### Directory Listing

- Files and directories are listed with their names, sizes, and last modified dates.
- Directories are displayed at the top of the list.
- Click on a directory name to navigate into it.
- Click on a file name to download or view it, depending on the file type.

### File Uploading

- Use the **File Upload** form on the page to upload files to the current directory.
- Select one or multiple files to upload.
- Uploaded files will appear in the directory listing after refreshing the page.

### Text Submission

- Use the **Submit Text** form to send text to the server.
- Submitted text is appended to a `submitted_text.txt` file in the current directory.

### Customizing the Interface

- The HTML and CSS code is embedded in the source code (specifically in the `send_directory_listing` function).
- You can modify the styling by editing the CSS strings in the code.
- For example, to change the alternating row colors in the directory listing table, adjust the CSS:

```c
"tr:nth-child(even) { background-color: #d0e7ff; }"  // Sky blue for even rows
"tr:nth-child(odd) { background-color: #c0c0c0; }"   // Silver for odd rows
```

- To change colors or add new styles, edit the corresponding CSS code and recompile the program.

## Compilation and Installation Details

### Makefile Targets

- **`make`**: Compiles the program.
- **`make clean`**: Removes compiled object files and the executable.
- **`make install`**: Installs the executable to `$(PREFIX)/bin` (default `/usr/local/bin`).
- **`make uninstall`**: Removes the installed executable.

### Customizing the Build

- **Compiler and Flags**: Modify `CC` and `CFLAGS` in the `Makefile` to change the compiler or compiler options.
- **Installation Prefix**: Set `PREFIX` when running `make install` to change the installation directory.

### Example

Compile with additional warnings and install to `/usr/bin`:

```bash
make CFLAGS="-Wall -Wextra -O2 -g"
sudo make install PREFIX=/usr
```

## Security Considerations

- **Input Sanitization**: The server sanitizes paths to prevent directory traversal attacks.
- **Permissions**: Run the server with appropriate permissions; avoid running as root.
- **File Overwriting**: Uploaded files with the same name as existing files will overwrite them. Ensure that this behavior is acceptable in your use case.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

MIT License

```
MIT License

Copyright (c) 2024 Mohammad Samadpour

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests on GitHub.

## Contact

For questions or suggestions, please contact me at delphi_coder at yahoo.com.

---

## Additional Information

### Editing and Modifying the Code

- **Source Files**: The main source code is in `main.c`. All the server functionality is implemented here.
- **Adding Features**: You can add new features by modifying `main.c` and recompiling the program.
- **Functionality Overview**:
  - **`handle_request`**: Handles incoming HTTP requests.
  - **`send_directory_listing`**: Generates and sends the directory listing page.
  - **`handle_file_upload`**: Processes file uploads from the client.
  - **`serve_file`**: Serves files for downloading or viewing.
  - **`handle_text_submission`**: Handles text submitted by the user.
  - **`sanitize_path`**: Ensures that input paths are safe and valid.

### Supported File Types and MIME Types

The server uses the file extension to determine the correct `Content-Type` header:

- **Text/HTML**: `text/html` for `.html` and `.htm` files.
- **Plain Text**: `text/plain` for `.txt` files.
- **CSS**: `text/css` for `.css` files.
- **JavaScript**: `application/javascript` for `.js` files.
- **Images**:
  - `image/jpeg` for `.jpg` and `.jpeg` files.
  - `image/png` for `.png` files.
  - `image/gif` for `.gif` files.
- **Others**: `application/octet-stream` for unrecognized file types, prompting download.

### Modifying Supported File Types

To add support for additional file types, modify the `serve_file` function in `main.c`:

```c
if (strcmp(extension, ".pdf") == 0) {
    content_type = "application/pdf";
    inline_display = 1;  // or 0 to prompt download
}
```

After making changes, recompile the program with `make`.

## Disclaimer

This server is intended for educational purposes and small-scale use. It may not be suitable for production environments without further enhancements and security audits.

---

**WebBridge** aims to bridge the gap between simplicity and functionality, providing an easy way to share files over HTTP with minimal setup. Enjoy exploring and customizing the server to fit your needs!
