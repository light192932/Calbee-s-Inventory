<?php
include 'db.php';?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet"
    integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.5.0/css/all.css">    
    <link href="css/styles.css" rel="stylesheet">
</head>
<body>
    <!--LOGO--->
	<div class="main" style="background: rgba(0, 0, 0, 0.5) url(cal-pic/calbees.jpg); background-position: bottom; background-size: cover; background-blend-mode: darken;;">
		<div class="logo">
				<H2 style="font-style:italic; color: #fff;">Calbee's Cafe<br> Your Daily Habit =)</H2></a>
			</div>

	         <!--MENU--->
			<nav class="bar">
				<a href="#">Home</a> 
				<a href="#popu">About</a>
				<a href="#foot">Contact</a>
				<button class='Fill-up' onclick="document.getElementById('login-form').style.display='block'">Login</button>
			</nav>

	         <!--HEADER--->		  
			<div class="head">
				<h2>#Calbee's Cafe Diner</h2>
				<div class="line"></div>
				<h1>A Local Casual Dining Café in Concepcion, Tarlac
				Food and Coffee enthusiast welcome to Calbee's cafe.</h1> 
			</div>     
				   
	          <!--LOGIN FORM-->
			  <div id='login-form' class='login-page'>
            <div class="form-box">
                <div class='button-box'>
                    <h1>Calbee's Cafe</h1>
                </div>
                <!-- Login Form -->
                <form id='login' method="post" class='input-group-login'>
                    <!-- Display error message above the username field if it exists -->
                    <input type='text' class='input-field' placeholder='username' name="user" required>
                    <input type='password' class='input-field' placeholder='Password' name="pass" required>
                    <input type='checkbox' class='check-box'><span class="log">Remember Password</span>
                    <button type='submit' class='submit-btn' value="Login" name="log">Log in</button>
                </form>
            </div>
        </div>
			  </div>

			<?php
	if (isset($_POST['log'])) {
        $uname = $_POST['user'];
        $pass = $_POST['pass'];
    
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $uname);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $row = $result->fetch_assoc(); 
            
            if (password_verify($pass, $row['password'])) {
                echo "<script>window.location.href='index.php'</script>";
            } else {
                echo "<script>alert('Invalid password. Please try again.');</script>";
            }
        } else {
            echo "<script>alert('No user found with that username.');</script>";
        }
        $stmt->close();
    }
  ?>

    <div class="container py-5" id="popu">
        <h1 class="text-center">Best Seller</h1>
        <div class="row row-cols-1 row-cols-md-3 g-4 py-5">
            <div class="col">
                <div class="card">
                    <img src="cal-pic/1.13.jpg" class="card-img-top" alt="...">
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <img src="cal-pic/1.jpg" class="card-img-top" alt="...">
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <img src="cal-pic/5.jpg" class="card-img-top" alt="...">
                </div>
            </div>
            <div class="col">
                <div class="card">
                    <img src="cal-pic/4.jpg" class="card-img-top" alt="...">
                    </div>
            </div>
            <div class="col">
                <div class="card">
                    <img src="cal-pic/14.jpg" class="card-img-top" alt="...">
                    </div>
            </div>
            <div class="col">
                <div class="card">
                    <img src="cal-pic/15.jpg" class="card-img-top" alt="...">
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
        crossorigin="anonymous"></script>

         <!--FOOTER-->
	  <footer class="footer" id="foot">
		<div class="containerss">
			<div class="rowww">
				<div class="footer-col">
					<h4 class="foot">company</h4>
					<ul>
						<li><a href="#">about us</a></li>
						<li><a href="#">our services</a></li>
						<li><a href="#">privacy policy</a></li>
						<li><a href="#">affiliate program</a></li>
					</ul>
				</div>
				<div class="footer-col">
					<h4 class="foot">Contact & Address</h4>
					<ul>
						<li>Address:<a href="#"></br>
                            137 Ilang-Ilang Street Rosepark, Concepcion, 2316 Tarlac, Philippines </br></a></li>
						<li style="color: #fff;">MOBILE NUMBER:<a href="#"></br>
                                        0905 194 8835</a></li>
					</ul>
				</div>
				<div class="footer-col">
					<h4 class="foot">OFFICE HOURS</h4>
					<ul>
						<li>Monday:
                            11:00AM - 9:00PM
                        </li>
						<li>Tuesday
                            11:00AM - 9:00PM</li>
						<li>Wednesday:
                            11:00AM - 9:00PM</li>
						<li>Thursday:
                            11:00AM - 9:00PM</li>
						<li>Friday:
                            11:00AM - 9:00PM</li>
						<li>Saturday:
                            11:00AM - 9:00PM</li>
						<li style="color: red;">Sunday:
							Closed</li>
					</ul>

				</div>
				<div class="footer-col">
					<h4 class="foot">follow us</h4>
					<div class="social-links">
						<a href="https://www.facebook.com/CalbeesCafeDinerOfficial"><i class="fab fa-facebook-f"></i></a>
					</div>
				</div>
			</div>
		</div>
   </footer>
		  
</body>
</html>
