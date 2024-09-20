 - [ ] List item

# 使用 Gorm 和 Gin 创建一个简单的 Go Web 用户管理系统

## 介绍

在这篇博客中，我们将使用 Go 语言结合 Gorm 和 Gin 框架，创建一个简单的用户管理系统。这个系统将实现用户的注册、登录、查看信息、更新信息等基本功能。我们将逐步介绍每一个步骤的实现，并解决遇到的问题。

## 项目初始化

### 1. 创建项目目录并初始化 Go 模块

首先，创建一个新的 Go 项目目录并初始化模块：


```bash
mkdir user-management
cd user-management
go mod init user-management
```
这将会在当前目录下生成一个 go.mod 文件，用于管理项目的依赖。

## 安装依赖
接下来，我们将安装项目所需的依赖库，包括 Gorm、Gin 以及用于数据库连接的 MySQL 驱动：

```bash
go get -u gorm.io/gorm
go get -u gorm.io/driver/mysql
go get -u github.com/gin-gonic/gin
go get -u github.com/golang-jwt/jwt/v4
```

这些依赖库将帮助我们处理数据库操作、HTTP 请求和用户认证。

## 配置数据库连接
在项目根目录下创建 main.go 文件，用于初始化数据库连接和启动服务器。首先，我们需要配置数据库连接。

在 main.go 文件中，添加以下代码：

```go
package main

import (
    "log"
    "user-management/controllers"
    "user-management/models"
    "github.com/gin-gonic/gin"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

var DB *gorm.DB

func initDB() {
    dsn := "username:password@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
    var err error
    models.DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }

    // 自动迁移，创建用户表
    err = models.DB.AutoMigrate(&models.User{})
    if err != nil {
        log.Fatalf("Failed to migrate database: %v", err)
    }

    log.Println("Database connected and migrated successfully!")
}

func main() {
    initDB()

    r := gin.Default()

    // 用户注册路由
    r.POST("/register", controllers.Register)

    // 启动服务器
    r.Run(":8080")
}
```
代码解释：
在上面的代码中，记得将 username、password 和 dbname 替换为你 MySQL 数据库的实际用户名、密码和数据库名称。

    initDB 函数：该函数负责初始化数据库连接。我们使用 Gorm 连接 MySQL 数据库，并配置了数据库的 DSN（数据源名称）。

    自动迁移：在连接成功后，我们调用 AutoMigrate 方法，将 User 模型自动迁移到数据库中，这会在数据库中创建一个 users 表。

    Gin 路由设置：我们使用 Gin 框架启动一个 HTTP 服务器，并设置了一个用户注册的 POST 路由。


## 创建数据库模型
接下来，我们需要定义用户模型。模型是数据库表的抽象表示。我们将在 models 目录下创建一个 user.go 文件。

首先，在项目根目录下创建 models 目录，然后在该目录下创建 user.go 文件，并添加以下代码：

```go
package models

import (
    "gorm.io/gorm"
)

// User 定义了用户的结构体
type User struct {
    gorm.Model
    Username string `gorm:"unique;not null"`
    Password string `gorm:"not null"`
}
```
代码解释：

    User 结构体：该结构体定义了 users 表的结构。gorm.Model 是 Gorm 提供的一个基础模型，它会自动包含
     ID、创建时间、更新时间等字段。Username 字段被设置为唯一且不能为空，Password 字段同样不能为空。

## 实现用户注册功能
现在我们来实现用户注册功能。当用户提交注册请求时，我们会将用户信息保存到数据库中。

在项目根目录下创建 controllers 目录，然后在该目录下创建 user.go 文件，并添加以下代码：

```go
package controllers

import (
    "net/http"
    "user-management/models"
    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/bcrypt"
)

func Register(c *gin.Context) {
    var input struct {
        Username string `json:"username" binding:"required"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }

    user := models.User{
        Username: input.Username,
        Password: string(hashedPassword),
    }

    if err := models.DB.Create(&user).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}
```
代码解释：

    Register 函数：该函数处理用户注册请求。首先，我们从请求中绑定 JSON 数据到 input 结构体中，
    然后使用 bcrypt 对用户密码进行加密，最后将用户数据保存到数据库中。如果一切正常，将返回一个成功消息。

## 实现用户登录功能
接下来，我们实现用户登录功能。登录成功后，系统会生成一个 JWT token。

在 controllers/user.go 文件中添加以下代码：

```go
package controllers

import (
    "net/http"
    "time"
    "user-management/models"
    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/bcrypt"
    "github.com/golang-jwt/jwt/v4"
)

// 你可以将这个密钥存储在环境变量或配置文件中
var jwtSecret = []byte("your-secret-key")

func generateToken(userID uint) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "id":  userID,
        "exp": time.Now().Add(time.Hour * 24).Unix(), // 24小时后过期
    })

    // 签名并生成 JWT 字符串
    return token.SignedString(jwtSecret)
}

func Login(c *gin.Context) {
    var input struct {
        Username string `json:"username" binding:"required"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var user models.User
    if err := models.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
        return
    }

    // 生成 JWT token
    token, err := generateToken(user.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": token})
}
```
代码解释：

    Login 函数：该函数处理用户登录请求。我们首先验证用户名和密码，然后生成一个 JWT token 并返回给客户端。

    generateToken 函数：该函数使用用户的 ID 生成一个 JWT token，并设置一个 24 小时的有效期。

## 实现用户信息管理功能
我们将实现两个功能：查看用户信息和更新用户信息。
1. 查看用户信息

在 controllers/user.go 文件中添加以下代码：

```go
func GetUserInfo(c *gin.Context) {
    userID := c.Param("id")
    
    var user models.User
    if err := models.DB.First(&user, userID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "id":       user.ID,
        "username": user.Username,
    })
}
```
代码解释：

    GetUserInfo 函数：该函数通过用户 ID 查询用户信息，并将用户的基本信息返回给客户端。

## 更新用户信息
在 controllers/user.go 文件中添加以下代码：

```go
func UpdateUser(c *gin.Context) {
    userID := c.Param("id")
    
    var user models.User
    if err := models.DB.First(&user, userID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }

    var input struct {
        Username string `json:"username"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    models.DB.Model(&user).Update("username", input.Username)

    c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}
```
代码解释：

    UpdateUser 函数：该函数允许用户更新自己的用户名。我们首先通过用户 ID 查询用户，然后更新用户名并保存到数据库中。

## 设置路由
最后，我们在 main.go 文件中设置所有的路由，并启动 Gin 服务器。

```go
package main

import (
    "user-management/controllers"
    "github.com/gin-gonic/gin"
)

func main() {
    initDB()

    r := gin.Default()

    // 用户注册路由
    r.POST("/register", controllers.Register)
    
    // 用户登录路由
    r.POST("/login", controllers.Login)
    
    // 用户信息管理路由
    r.GET("/users/:id", controllers.GetUserInfo)
    r.PUT("/users/:id", controllers.UpdateUser)

    // 启动服务器
    r.Run(":8080")
}
```
代码解释：

    路由配置：我们在 Gin 中设置了几个路由来处理用户注册、登录、查看信息和更新信息的请求。


## 使用 Postman 测试 API

在实现了 API 之后，我们可以使用 Postman 对其进行测试。以下是如何使用 Postman 测试各个功能的详细步骤。

### 1. 测试用户注册功能

1. 打开 Postman，创建一个新的请求。
2. 设置请求类型为 `POST`。
3. 在 URL 中输入 `http://localhost:8080/register`。
4. 点击下方的 "Body" 标签，选择 `raw`，并将右侧的 `Text` 类型改为 `JSON`。
5. 在请求体中输入以下 JSON 数据：

    ```json
    {
        "username": "testuser",
        "password": "password123"
    }
    ```

6. 点击 “Send” 按钮发送请求。

如果注册成功，你会看到如下响应：


```json
{
    "message": "User registered successfully"
}
```

### 2. 测试用户登录功能
将上面第3步的URL改成http://localhost:8080/login即可。

如果登录成功，你会看到类似如下的响应，其中包含一个 JWT token：

```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 3. 测试查看用户信息功能
1. 设置请求类型为 `GET`。
2. 在 URL 中输入 `http://localhost:8080/users/1`。（假设用户 ID 是 1）
3. 点击 “Send” 按钮发送请求。

如果查询成功，你会看到如下响应：

```json
{
    "id": 1,
    "username": "testuser"
}
```

## 4. 测试更新用户信息功能
1. 设置请求类型为 `PUT`。
2. 在 URL 中输入 `http://localhost:8080/users/1`。（假设用户 ID 是 1）
3. 在请求体中输入以下 JSON 数据：

```bash
{
    "username": "newusername"
}. 
```

4. 点击 “Send” 按钮发送请求。

如果更新成功，你会看到如下响应：

```json
{
    "message": "User updated successfully"
}
```

通过这篇博客，我们从头到尾实现了一个简单的 Go Web 用户管理系统并进行了测试，涵盖了用户注册、登录、查看和更新信息等基本功能。尽管我们跳过了一些高级功能（如 JWT 中间件），但我们已经搭建了一个基础框架，可以在此基础上进一步扩展和优化。

如果你有任何问题或建议，欢迎在评论区留言！


