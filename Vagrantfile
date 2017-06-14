
Vagrant.configure("2") do |c|
  c.vm.box = "ubuntu/xenial64"
  c.vm.box_url = "https://atlas.hashicorp.com/ubuntu/boxes/trusty32/versions/14.04/providers/virtualbox.box"
  c.vm.synced_folder ".", "/vagrant", disabled: true

  c.vm.provider :virtualbox do |p|
    # http://help.appveyor.com/discussions/problems/1247-vagrant-not-working-inside-appveyor#comment_39277805
    p.customize ["modifyvm", :id, "--nictype1", "Am79C973"]

    p.customize ["modifyvm", :id, "--memory", "128"]
    p.gui = true
  end
end
