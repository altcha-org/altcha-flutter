Pod::Spec.new do |s|
  s.name             = 'altcha_widget'
  s.version          = '2.0.2'
  s.summary          = 'ALTCHA Flutter widget.'
  s.description      = 'Privacy-first, accessible CAPTCHA widget.'
  s.homepage         = 'https://altcha.org'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { 'Daniel Regeci' => '536331+ovx@users.noreply.github.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'
  s.platform         = :osx, '10.14'
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
  }
  s.swift_version    = '5.0'
end
