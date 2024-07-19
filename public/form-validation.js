document.addEventListener("DOMContentLoaded", function() {
    const form = document.getElementById('signUpForm');
    const submitButton = document.getElementById('submit');
  
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const phnoInput = document.getElementById('phno');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
  
    const nameError = document.getElementById('nameError');
    const emailError = document.getElementById('emailError');
    const phnoError = document.getElementById('phnoError');
    const usernameError = document.getElementById('usernameError');
    const passwordError = document.getElementById('passwordError');
  
    const isValidName = () => nameInput.value.trim() !== '';
    const isValidEmail = () => /\S+@\S+\.\S+/.test(emailInput.value);
    const isValidPhno = () => /^\d{10}$/.test(phnoInput.value);
    const isValidUsername = () => usernameInput.value.trim() !== '';
    const isValidPassword = () => passwordInput.value.length >= 6;
  
    const validateForm = () => {
      let isValid = true;
  
      if (!isValidName()) {
        nameError.textContent = 'Name is required';
        isValid = false;
      } else {
        nameError.textContent = '';
      }
  
      if (!isValidEmail()) {
        emailError.textContent = 'Email is not valid';
        isValid = false;
      } else {
        emailError.textContent = '';
      }
  
      if (!isValidPhno()) {
        phnoError.textContent = 'Phone number is not valid';
        isValid = false;
      } else {
        phnoError.textContent = '';
      }
  
      if (!isValidUsername()) {
        usernameError.textContent = 'Username is required';
        isValid = false;
      } else {
        usernameError.textContent = '';
      }
  
      if (!isValidPassword()) {
        passwordError.textContent = 'Password must be at least 6 characters long';
        isValid = false;
      } else {
        passwordError.textContent = '';
      }
  
      submitButton.disabled = !isValid;
    };
  
    form.addEventListener('input', validateForm);
  });
  