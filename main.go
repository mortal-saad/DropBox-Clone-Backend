package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"path/filepath"
)
type User struct {
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Used int `json:"used"`
}
type Share struct{
	Id string
	Fpath string
	Fowner string
	Permissions string
}
type UserCredentails struct{
	Email string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}
type Session struct{
	Token string
	Email string
	CreatedAt *time.Time
	ExpiresAt *time.Time
}
type PathModel struct{
	Path string `json:"path" binding:"required"`
}
var db *sql.DB
var alphabets="abcdefghijklmnopqrstuvwxyz0123456789"
func main(){
	gin.SetMode(gin.ReleaseMode)
	initDb()
	router:=gin.Default()
	fmt.Println("Server Running on http://127.0.0.1:8080")
	router.POST("/signUp",signUp)
	router.POST("/login",login)
	router.GET("/logout",logout)
	router.POST("/upload",authHandler(),uploadFile)
	router.POST("/mkdir",authHandler(),mkdir)
	router.GET("/getSize",authHandler(),func(ctx *gin.Context) {
		size,err:=getSize(ctx.GetString("email"))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError,"Failed to get Size")
			return
		}
		ctx.JSON(http.StatusOK,gin.H{
			"size":size,
		})
	})
	router.GET("/files/*filepath",authHandler(),getFile)
	router.POST("/list",authHandler(),list)
	router.DELETE("/delete",authHandler(),delete)
	err:=router.Run(":8080")
	if err!=nil{
		fmt.Println("Error Running Server")
	}
}
func initDb(){
	var err error
	db,err=sql.Open("mysql","root:root(9)@tcp(127.0.0.1:3306)/DropBox?parseTime=true")
	if err!=nil{
		fmt.Println("Error Opening Connection to Database")
		return
	}
	err=db.Ping()
	if err != nil {
		fmt.Println("Error Pinging Database")
		return
	}
	fmt.Println("Connected to Database")
}
func generateString(x int) string{
	var out=""
	for range x{ 
		out+=string(alphabets[mrand.Intn(len(alphabets))])
	}
	return out
}
func generateToken()(string,error){
	b:=make([]byte,32)
    _,err:=crand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b),nil
}
func hashToken(t string)string{
	sum:=sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
func authHandler()gin.HandlerFunc{
	return func(c *gin.Context) {
		if email,exists:=c.Get("email");exists && email!=""{
			c.Next()
			return
		}
		authHeader:=c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{
				"error":"missing auth",
			})
			return
		}
		const prefix="Bearer "
		if len(authHeader) <= len(prefix) ||
		   authHeader[:len(prefix)] != prefix {
			c.AbortWithStatus(401)
			return
		}
		token:=authHeader[len(prefix):]
		hashedToken:=hashToken(token)
		session,err:=getSession(hashedToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound,"Session Not Found")
			return
		}
		storedToken,err:=getToken(session.Email)
		if err != nil{
			c.AbortWithStatusJSON(http.StatusUnauthorized,"Token Expired or Non Existent")
			return
		}
		if storedToken==hashedToken{
			c.Set("email",session.Email)
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized,"Token Expired or Non Existent")
	}
}
func login(c *gin.Context){
	var user UserCredentails
	var password string
	if err:=c.BindJSON(&user);err!=nil{
		c.JSON(http.StatusBadRequest,"Required Field(s) Missing")
		return
	}
	err:=db.QueryRow("Select pass from Users where email=?",user.Email).Scan(&password)
	if err!=nil{
		c.JSON(http.StatusInternalServerError,"Failed to Fetch Credentials From Database")
		return
	}
	if password!=user.Password{
		c.JSON(http.StatusForbidden,"Incorrect Credentials")
		return
	}
		token, err := generateToken()
		if err != nil {
			c.JSON(500,"Token Generation failed")
			return
		}
		tokenHash := hashToken(token)
		err=insertToken(tokenHash,user.Email)
		if err != nil {
			c.JSON(500,"Saving Token failed")
			return
		}
		c.JSON(http.StatusOK,gin.H{"access_token":token})
		return
}
func logout(c *gin.Context){
	c.Set("email","")
}
func signUp(c *gin.Context){
	var user User
	if err:=c.BindJSON(&user);err!=nil{
		c.JSON(http.StatusBadRequest,"Required Field(s) Missing")
		return
	}
	success,err:=insertUser(user)
	if err!=nil{
		fmt.Println("Error Inserting User in DB",err)
		c.JSON(http.StatusInternalServerError,"Failed to Insert User in DB")
		return
	}
	if !success{
		c.JSON(http.StatusConflict,"User with provided email exists")
		return
	}
	c.JSON(http.StatusCreated,"Success")
	os.Mkdir("./uploads/"+strings.Split(user.Email,"@")[0],0755)
}
func getUser(email string)(*User,bool){
	var user User
	err:=db.QueryRow("Select * from Users where email=?",email).Scan(&user.Name,&user.Password,&user.Email,&user.Used)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false
		}
		return nil, false
	}
	return &user, true
}
func insertUser(user User)(bool,error){
	_,exist:=getUser(user.Email)
	if exist{
		return false,nil
	}
	_,err:=db.Exec("insert into Users(name,pass,email) values(?,?,?)",user.Name,user.Password,user.Email)
	if err!=nil{
		return false,err
	}
	return true,nil
}
func insertToken(token string,email string)error{
	_,err:=db.Exec("insert into Sessions(token,email) values(?,?)",token,email)
	return err
}
func getSession(token string)(*Session,error){
	var session Session
	err:=db.QueryRow("select * from Sessions where token=?",token).Scan(&session.Token,&session.Email,&session.CreatedAt,&session.ExpiresAt)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &session,nil
}
func getToken(email string)(string,error){
	var token string
	err:=db.QueryRow("Select token from Sessions where email=? and expiresAt > current_timestamp order by createdAt DESC limit 1",email).Scan(&token)
	if err != nil {
		return "", err
	}
	return token,nil
}
func uploadFile(c *gin.Context){
	file,err:=c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest,"File missing!")
		return
	}
	fpath:=c.PostForm("path")
	if fpath==""{
		c.JSON(http.StatusBadRequest,"Path Missing!")
		return
	}
	cleanPath:=strings.Trim(path.Clean(fpath),`"`)
	if strings.Contains(cleanPath,".."){
		c.JSON(http.StatusBadRequest,"Invalid Path!")
		return
	}
	email:=c.GetString("email")
	

	err=c.SaveUploadedFile(file,"./uploads/"+strings.Split(email,"@")[0]+"/"+cleanPath+"/"+file.Filename);
	if err != nil {
		c.JSON(http.StatusInternalServerError,"File Upload Failed")
		return;
	}
	sizeModify(email,file.Size)
	c.JSON(http.StatusOK,gin.H{
		"message":"File Upload Success",
		"size":file.Size,
	})
}
func mkdir(c *gin.Context){
	var fpath PathModel
	if err:=c.BindJSON(&fpath);err!=nil{
		c.JSON(http.StatusBadRequest,"Path Missing!")
		return
	}
	email:=c.GetString("email")
	cleanPath:=strings.Trim(path.Clean(fpath.Path),`"`)
	if strings.Contains(cleanPath,".."){
		c.JSON(http.StatusBadRequest,"Invalid Path!")
		return
	}
	err:=os.MkdirAll("./uploads/"+strings.Split(email,"@")[0]+"/"+cleanPath,0755)
	if err != nil {
		c.JSON(http.StatusInternalServerError,"Directory Creation Failed!")
		return
	}
	c.JSON(http.StatusOK,"Directory created")
}
func sizeModify(email string,size int64)bool{
	s,err:=getSize(email)
	if err != nil {
		return false
	}
	_,err=db.Exec("update Users set used=? where email=?",s+size,email)
	if err != nil {
		return false
	}
	return true
}
func getSize(email string)(int64,error){
	var size int64
	err:=db.QueryRow("select used from Users where email=?",email).Scan(&size)
	if err != nil {
		return 0,err
	}
	return size,nil
}
func list(c *gin.Context){
	var fpath PathModel
	if err:=c.BindJSON(&fpath);err!=nil{
		c.JSON(http.StatusBadRequest,"Path Missing!")
		return
	}
	cleanPath:=strings.Trim(path.Clean(fpath.Path),`"`)
	if strings.Contains(cleanPath,".."){
		c.JSON(http.StatusBadRequest,"Invalid Path!")
		return
	}
	name:=strings.Split(c.GetString("email"),"@")[0]
	entries,err:=os.ReadDir(fmt.Sprintf("./uploads/%s/%s",name,cleanPath))
	if err != nil {
		c.JSON(http.StatusInternalServerError,"Failed to Read Entries in drive!")
		return
	}
	var result []gin.H
	for _,entry:=range entries{
		info,_:=entry.Info()
		result = append(result, gin.H{
			"name":entry.Name(),
			"isDir":entry.IsDir(),
			"time":info.ModTime().Local().Format("02 Jan 2006 15:04"),
		})
	}
	c.JSON(http.StatusOK,result)
}
func delete(c *gin.Context){
	var fpath PathModel 
	var size int64
	if err:=c.BindJSON(&fpath);err!=nil{
		c.JSON(http.StatusBadRequest,"Path Missing!")
		return
	}
	cleanPath:=strings.Trim(path.Clean(fpath.Path),`"`)
	if strings.Contains(cleanPath,".."){
		c.JSON(http.StatusBadRequest,"Invalid Path!")
		return
	}
	email:=c.GetString("email")
	name:=strings.Split(email,"@")[0]
	desPath:=fmt.Sprintf("./uploads/%s/%s",name,cleanPath)
	filepath.Walk(desPath,func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			size += info.Size()
		}

		return nil
	})
	err:=os.RemoveAll(desPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError,"Failed to delete!")
		return
	}
	sizeModify(email,-size)
	c.JSON(http.StatusOK,"Deletion Success")
}
func getFile(c *gin.Context){
	file:=c.Param("filepath")
	file=filepath.Clean(file)
	user:=strings.Split(c.GetString("email"),"@")[0]
	fullPath:=filepath.Join("./uploads",user,file)

	info,err:=os.Stat(fullPath)

	if err != nil {
		c.JSON(http.StatusNotFound,"Path Not Found")
		return
	}

	if info.IsDir(){
		c.JSON(http.StatusBadRequest,"Target is a directory not a file")
		return
	}
	c.File(fullPath)
}

