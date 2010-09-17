spec = Gem::Specification.new do |s|
	s.name = 'xmlsec-ruby'
	s.version = '0.0.2'
	s.summary = 'Ruby bindings for xmlsec1'
	s.extensions = ['ext/xmlsec/extconf.rb']
	s.files = ["ext/xmlsec/simple-xmlsec.c", "ext/xmlsec/simple-xmlsec_wrap.c"]
	s.author = 'Victor Lin'
	s.email = 'victor@coupa.com'
	s.homepage = 'http://github.com/wonnage/xmlsec-ruby'
	s.description = <<-EOF
	xmlsec-ruby is an attempt to use SWIG to create ruby bindings
	for the xmlsec library (http://www.aleksey.com/xmlsec/). 
	Usage:
		Xmlsec.verify_file(xml_document_string, pem_certificate_string)
		Returns 0/1 on failure/success.
	This is actually the only function implemented so far. 
	EOF
end
