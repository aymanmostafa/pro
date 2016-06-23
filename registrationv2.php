<!DOCTYPE HTML>  
<html>
<head>
<style>
.error {color: #FF0000;}
</style>
</head>
<body>  

<?php
$link = mysqli_connect("localhost","cl59-aymandb-500","13851385","cl59-aymandb-500");
 if(mysqli_connect_error()){
	 echo "Database Connection Error, Please try again later..";
	 die();
 }
// define variables and set to empty values
$usernameErr = $emailErr = $genderErr = $passwordErr = $password2Err = $checkErr = "";
$username = $email = $gender = $password = $password2 = $check = "";
$userlog = $passlog = "";
$userlogErr = $passlogErr = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
	if($_POST["submit"]=='Sign up'){
  if (empty($_POST["username"])) {
    $usernameErr = "*Username is required";
  } else {
    $username = test_input($_POST["username"]);
    if (!preg_match("/^[a-zA-Z0-9 ]/",$username)) {
      $usernameErr = "*Only letters and numbers are allowed"; 
    }
  }
 
  if (empty($_POST["email"])) {
    $emailErr = "*E-mail is required";
  } else {
    $email = test_input($_POST["email"]);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $emailErr = "*Invalid email format"; 
    }
  }
    
	if (empty($_POST["password"])) {
    $passwordErr = "*Password is required";
  } else {
    $password = test_input_password($_POST["password"]);
    if(!preg_match('/^(?=.*\d)(?=.*[A-Za-z])[0-9A-Za-z!@#)($%]{8,50}$/', $password)) {
      $passwordErr = "*Invalid password format"; 
    }
  }
  
  if (empty($_POST["password2"])) {
    $password2Err = "*Password confirmation is required";
  } else {
    $password2 = test_input_password($_POST["password2"]);
    if($_POST['password']!= $_POST["password2"]) {
      $password2Err = "*Passwords do not match"; 
    }
  }

  if (empty($_POST["check"])) {
    $checkErr = "*You must confirm your age";
  } else {
    $check = test_input($_POST["check"]);
  }

  if (empty($_POST["gender"])) {
    $genderErr = "*Please choose your gender";
  } else {
    $gender = test_input($_POST["gender"]);
  }
	}
	
  //log-in
  else if($_POST["submit"]=='login'){if (empty($_POST["userlog"])) {
    $userlogErr = "*Username is required";
  } else {
    $userlog = test_input($_POST["userlog"]);
    if (!preg_match("/^[a-zA-Z0-9 ]/",$userlog)) {
      $userlogErr = "*invalid username"; 
    }
  }
  
  if (empty($_POST["passlog"])) {
    $passlogErr = "*Password is required";
  } else {
    $passlog = test_input_password($_POST["passlog"]);
  }
  }
}

function test_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;
}
function test_input_password($data) {
  $data = htmlspecialchars($data);
  return $data;
}
?>

<h1>login!</h1>
<form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">  
  Username: <input type="text" name="userlog" value="<?php echo $userlog;?>">
  <span class="error"> <?php echo $userlogErr;?></span>
  <br><br>
  Password: <input type="password" name="passlog" value="<?php echo $passlog;?>">
  <span class="error"> <?php echo $passlogErr;?></span>
  <br><br>
  <input type="submit" name="submit" value="login">  
</form>



<?php

if($userlog != "" && $passlog != "" && $userlogErr == "" && $passlogErr == ""){
	
	$userlogexist = $passlogexist = "";
	
	$stmt = $link->prepare("select `username` , `password` from `users` where `username` = ?");
		if(!$stmt){
			echo "Error at Database, Please try again later";
	        die();
		}
		$stmt->bind_param("s", $userlog);
		if(!$stmt){
			echo "Error at Database, Please try again later";
	        die();
		}
		
		$stmt->execute();
		$stmt->bind_result($userlogexist,$passlogexist);
        $stmt->fetch();
		$stmt->close();
		
		if($userlogexist == $userlog && $passlogexist == md5(md5($passlog))){
			echo "Successfully logged in!";
		}
	else{
		echo '<span style="color:#FF0000;text-align:center;">username or password is wrong!</span>';
		
	}
	$link->close();
}
?>
<h1>Sign up!</h1>
<form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">  
  Username: <input type="text" name="username" value="<?php echo $username;?>">
  <span class="error"> <?php echo $usernameErr;?></span>
  <br><br>
  E-mail: <input type="text" name="email" value="<?php echo $email;?>">
  <span class="error"> <?php echo $emailErr;?></span>
  <br><br>
  Password: <input type="password" name="password" value="<?php echo $password;?>">
  <span class="error"> <?php echo $passwordErr;?></span>
  <br><br>
  Confirm password: <input type="password" name="password2" value="<?php echo $password2;?>">
  <span class="error"> <?php echo $password2Err;?></span>
  <br><br>
  Gender:
  <input type="radio" name="gender" <?php if (isset($gender) && $gender=="female") echo "checked";?> value="female">Female
  <input type="radio" name="gender" <?php if (isset($gender) && $gender=="male") echo "checked";?> value="male">Male
  <span class="error"> <?php echo $genderErr;?></span>
  <br><br>
  I'm over 13 years old :
  <input type="checkbox" name="check" <?php if (isset($check) && $check=="above") echo "checked";?> value="above">
  <span class="error"> <?php echo $checkErr;?></span>
  <br><br>
  <input type="submit" name="submit" value="Sign up">  
</form>
<?php
echo "<br>";

if($usernameErr == "" && $emailErr == "" && $passwordErr == "" && $password2Err == "" && $genderErr == "" && $checkErr == ""
&& $username != "" && $email != "" && $password != "" && $gender != "" && $check != ""){
	
	$shouldDie=false;
	$userexist = $emailexist = "";
	
	$stmt = $link->prepare("select `username` from `users` where `username` = ?");
		if(!$stmt){
			echo "Error at Database, Try again";
	        die();
		}
		$stmt->bind_param("s", $username);
		if(!$stmt){
			echo "Error at Database, Try again";
	        die();
		}
		$stmt->execute();
		$stmt->bind_result($userexist);
        $stmt->fetch();
		$stmt->close();

	if($userexist != "")
	{
		echo "This username already exists</br>";
		$shouldDie=true;
	}
	
	$stmt = $link->prepare("select `email` from `users` where `email` = ?");
		if(!$stmt){
			echo "Error at Database, Try again1";
	        die();
		}
		$stmt->bind_param("s", $email);
		if(!$stmt){
			echo "Error at Database, Try again2";
	        die();
		}
		$stmt->execute();
		$stmt->bind_result($emailexist);
        $stmt->fetch();
	
	if($emailexist != ""){
		echo "This E-mail already exists";
		$shouldDie=true;
	}
	$stmt->close();
	
	if(!$shouldDie)
	{
	
		$stmt = $link->prepare("INSERT INTO `users` (`username`,`email`,`password`,`gender`) VALUES (?,?,?,?)");
		if(!$stmt){
			echo "Error at Database, Try again";
	        die();
		}
		
		$stmt->bind_param("ssss", $username,$email,md5(md5($password)),$gender);
		if(!$stmt){
			echo "Error at Database, Try again";
	        die();
		}
		$stmt->execute();
		$stmt->close();
		$link->close();
		
		echo "you have been successfully signed up!";
		//mail($email,"Welcome to TrendyZ"," "," ");
	}
}
if($passwordErr == "*Invalid password format") {
	echo '<span style="color:#FF0000;text-align:center;">Password must be at least 8 characters and contains one letter and one number:</br>
	*Allowed special characters are: )!@#$%( </br></span>';
}
?>


</body>
</html>